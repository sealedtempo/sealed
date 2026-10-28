import { describe, expect, it } from 'vitest'
import type { ChargePreflight, PaymentResult, Payments } from '../src/payments.js'
import { parsePriceTable } from '../src/prices.js'
import { MAX_FIRST_BYTE_WAIT_MS, SETTLE_MARGIN_MS, createRelayApp } from '../src/server.js'
import { Upstream } from '../src/upstream.js'
import { fakeLiteLLM } from './helpers/fake-litellm.js'

const prices = parsePriceTable(
  {
    currency: '0x20c0000000000000000000000000000000000000',
    decimals: 6,
    models: [{ id: 'tinfoil/gpt-oss-120b', provider: 'tinfoil', upstream_model: 'gpt-oss-120b', input_per_1m: 240000, output_per_1m: 780000, max_output_tokens: 128 }],
  },
  500,
)
const gate = { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] } as never

/**
 * Review finding M3 (relay side): a per-request charge is settled only after the upstream
 * answered and produced its first byte, so an upstream that fails before that never costs the
 * payer a charge.
 */
function relay(options: { preflight?: ChargePreflight; settle?: 'ok' | '402'; upstream: (init: RequestInit) => Promise<Response>; now?: () => number }) {
  const events: string[] = []
  const handled: Request[] = []
  const payments: Payments = {
    sessionsEnabled: false,
    preflightCharge: async () => options.preflight ?? { kind: 'valid' },
    async handle(request): Promise<PaymentResult> {
      handled.push(request)
      events.push('settle')
      if (options.settle === '402' || !request.headers.get('authorization')) return { status: 402, challenge: new Response('pay', { status: 402 }) }
      return {
        status: 200,
        intent: 'charge',
        withReceipt: (r) => {
          const res = r as Response
          res.headers.set('payment-receipt', 'receipt')
          return res
        },
      }
    },
    credit: async () => 'credited',
  }
  const app = createRelayApp({
    prices,
    gate,
    payments,
    upstream: new Upstream({
      baseURL: 'http://litellm/v1',
      apiKey: 'k',
      fetch: async (_url, init) => {
        events.push('upstream')
        return options.upstream(init ?? {})
      },
    }),
    batchTokens: 8,
    now: options.now,
  })
  const call = () =>
    app.request('/v1/chat/completions', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Payment test' },
      body: JSON.stringify({ model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'hi' }], stream: true }),
    })
  return { call, events, handled }
}

describe('per-request charges settle after the upstream first byte (M3)', () => {
  it('calls the upstream first, then settles, then streams with the receipt', async () => {
    const llm = fakeLiteLLM({ words: ['a', 'b'] })
    const r = relay({ upstream: (init) => llm.fetch('http://litellm/v1/chat/completions', init) })
    const res = await r.call()
    expect(res.status).toBe(200)
    expect(res.headers.get('payment-receipt')).toBe('receipt')
    expect(await res.text()).toContain('"content":"b"')
    expect(r.events).toEqual(['upstream', 'settle'])
  })

  it.each([
    ['answers 500', async () => Response.json({ error: { message: 'boom' } }, { status: 500 }), 500],
    ['rate-limits', async () => Response.json({ error: { message: 'slow down' } }, { status: 429 }), 429],
    ['is unreachable', async () => Promise.reject(new TypeError('fetch failed')), 502],
    ['ends before any byte', async () => new Response(new ReadableStream({ start: (c) => c.close() }), { headers: { 'content-type': 'text/event-stream' } }), 502],
  ])('takes no charge when the upstream %s', async (_name, upstream, status) => {
    const r = relay({ upstream: upstream as () => Promise<Response> })
    const res = await r.call()
    expect(res.status).toBe(status)
    expect(res.headers.get('payment-receipt')).toBeNull()
    expect((await res.json()).error).toMatchObject({ charged: false })
    expect(r.events).not.toContain('settle')
  })

  it('refuses without charging when the first byte would come too close to the payment expiry', async () => {
    const t = 1_000_000_000_000
    let aborted = false
    const r = relay({
      preflight: { kind: 'valid', validBefore: Math.floor(t / 1000) + 8 },
      now: () => t,
      upstream: (init) =>
        new Promise((_, reject) => {
          init.signal?.addEventListener('abort', () => {
            aborted = true
            reject(new DOMException('aborted', 'AbortError'))
          })
        }),
    })
    const started = Date.now()
    const res = await r.call()
    expect(res.status).toBe(504)
    expect((await res.json()).error).toMatchObject({ type: 'upstream_timeout', charged: false })
    expect(r.events).toEqual(['upstream'])
    expect(aborted).toBe(true)
    // 8 s of validity minus the settle margin leaves 2 s to wait.
    expect(Date.now() - started).toBeLessThan(8_000 - SETTLE_MARGIN_MS + 1_500)
    expect(MAX_FIRST_BYTE_WAIT_MS).toBeGreaterThan(SETTLE_MARGIN_MS)
  })

  it('cancels the upstream and answers 402 when the charge does not settle', async () => {
    let cancelled = false
    const r = relay({
      settle: '402',
      upstream: async () =>
        new Response(
          new ReadableStream({
            start: (c) => c.enqueue(new TextEncoder().encode('data: {"choices":[]}\n\n')),
            cancel: () => void (cancelled = true),
          }),
          { headers: { 'content-type': 'text/event-stream' } },
        ),
    })
    const res = await r.call()
    expect(res.status).toBe(402)
    expect(cancelled).toBe(true)
  })

  it('answers a charge credential that fails the preflight with a fresh challenge, never handing it to mppx', async () => {
    const r = relay({ preflight: { kind: 'invalid' }, upstream: async () => new Response('never') })
    const res = await r.call()
    expect(res.status).toBe(402)
    expect(r.events).toEqual(['settle'])
    expect(r.handled[0]!.headers.get('authorization')).toBeNull()
  })
})
