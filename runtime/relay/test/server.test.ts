import { describe, expect, it } from 'vitest'
import type { Payments, PaymentResult } from '../src/payments.js'
import { type PriceTable, costInBaseUnits, parsePriceTable } from '../src/prices.js'
import type { ProviderStatus } from '../src/providers/types.js'
import { boundedMaxTokens, createRelayApp, perRequestPrice } from '../src/server.js'
import { Upstream } from '../src/upstream.js'
import { fakeLiteLLM } from './helpers/fake-litellm.js'

const prices: PriceTable = parsePriceTable(
  {
    currency: '0x20c0000000000000000000000000000000000000',
    decimals: 6,
    default_max_tokens: 256,
    default_models: ['tinfoil/gpt-oss-120b', 'nearai/z-ai/glm-5.3'],
    models: [
      { id: 'tinfoil/gpt-oss-120b', provider: 'tinfoil', upstream_model: 'gpt-oss-120b', input_per_1m: 240000, output_per_1m: 780000, max_output_tokens: 512 },
      { id: 'nearai/z-ai/glm-5.3', provider: 'nearai', upstream_model: 'z-ai/glm-5.3', input_per_1m: 1800000, output_per_1m: 5750000 },
    ],
  },
  500,
)

function gate(verified: Record<string, boolean>) {
  const status = (provider: string): ProviderStatus => ({
    provider: provider as ProviderStatus['provider'],
    enabled: provider in verified,
    verified: verified[provider] === true,
    detail: verified[provider] ? 'attestation verified' : 'quote: bad measurement',
  })
  return {
    allows: (p: string) => status(p).enabled && status(p).verified,
    status,
    all: () => ['tinfoil', 'nearai'].map(status),
  } as never
}

type Recorded = { offers: { chargeAmount?: bigint; description?: string }[]; credits: bigint[] }

function payments(intent: 'none' | 'charge' | 'session', recorded: Recorded): Payments {
  return {
    sessionsEnabled: true,
    async preflightCharge() {
      return intent === 'charge' ? { kind: 'valid' } : { kind: 'none' }
    },
    async handle(_request, offers): Promise<PaymentResult> {
      recorded.offers.push(offers)
      if (intent === 'none') return { status: 402, challenge: new Response('pay', { status: 402 }) }
      if (intent === 'charge')
        return { status: 200, intent: 'charge', withReceipt: (r) => { const res = r as Response; res.headers.set('payment-receipt', 'charge-receipt'); return res } }
      return {
        status: 200,
        intent: 'session',
        channelId: `0x${'ab'.repeat(32)}`,
        withReceipt: (gen) => {
          if (typeof gen !== 'function') throw new Error('expected a generator')
          const charges: bigint[] = []
          const stream = { charge: async (a?: bigint) => void charges.push(a ?? 1n), signal: new AbortController().signal }
          const iterator = (gen as (s: typeof stream) => AsyncIterable<string>)(stream)
          const encoder = new TextEncoder()
          const body = new ReadableStream<Uint8Array>({
            async start(controller) {
              for await (const data of iterator) controller.enqueue(encoder.encode(`event: message\ndata: ${data}\n\n`))
              controller.enqueue(encoder.encode(`event: payment-receipt\ndata: ${JSON.stringify({ charged: charges.reduce((a, b) => a + b, 0n).toString() })}\n\n`))
              controller.close()
            },
          })
          return new Response(body, { headers: { 'content-type': 'text/event-stream' } })
        },
      }
    },
    async credit(_channel, amount) {
      recorded.credits.push(amount)
      return 'credited'
    },
  }
}

function app(intent: 'none' | 'charge' | 'session', verified: Record<string, boolean> = { tinfoil: true, nearai: true }, llm = fakeLiteLLM()) {
  const recorded: Recorded = { offers: [], credits: [] }
  const logs: Record<string, unknown>[] = []
  const usage: Record<string, unknown>[] = []
  const relay = createRelayApp({
    prices,
    gate: gate(verified),
    payments: payments(intent, recorded),
    upstream: new Upstream({ baseURL: 'http://litellm:4000/v1', apiKey: 'sk-master', fetch: llm.fetch }),
    batchTokens: 8,
    log: (e) => logs.push(e),
    onUsage: (e) => usage.push(e),
  })
  return { relay, recorded, logs, llm, usage }
}

const chat = (body: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
const messages = [{ role: 'user', content: 'Say hello' }]

describe('relay front', () => {
  it('publishes models with relay prices and attestation state', async () => {
    const { relay } = app('none', { tinfoil: true, nearai: false })
    const doc = await (await relay.request('/v1/models')).json()
    const tinfoil = doc.data.find((m: any) => m.id === 'tinfoil/gpt-oss-120b')
    expect(tinfoil.sealed).toMatchObject({ provider: 'tinfoil', available: true, attested: true })
    expect(tinfoil.sealed.price).toMatchObject({ markup_bps: 500, input_per_1m: '252000', output_per_1m: '819000', list_input_per_1m: '240000' })
    expect(doc.data.find((m: any) => m.id === 'nearai/z-ai/glm-5.3').sealed.available).toBe(false)
    const status = await (await relay.request('/v1/attest-status')).json()
    expect(status.providers.nearai).toMatchObject({ verified: false, detail: 'quote: bad measurement' })
  })

  it('resolves the default model to the first preferred usable provider', async () => {
    const { relay, recorded } = app('none', { tinfoil: false, nearai: true })
    await relay.request('/v1/chat/completions', chat({ model: 'default', messages }))
    expect(recorded.offers[0]!.description).toMatch(/^nearai\/z-ai\/glm-5.3/)
    const doc = await (await relay.request('/v1/models')).json()
    expect(doc.default_model).toBe('nearai/z-ai/glm-5.3')
  })

  it('rejects unknown models and refuses providers whose attestation failed, before any payment', async () => {
    const { relay, recorded, llm } = app('charge', { tinfoil: true, nearai: false })
    expect((await relay.request('/v1/chat/completions', chat({ model: 'nope', messages }))).status).toBe(404)
    const refused = await relay.request('/v1/chat/completions', chat({ model: 'nearai/z-ai/glm-5.3', messages }))
    expect(refused.status).toBe(503)
    expect((await refused.json()).error).toMatchObject({ type: 'attestation_failed', provider: 'nearai' })
    expect(recorded.offers).toEqual([])
    expect(llm.calls).toEqual([])
  })

  it('offers a per-request charge priced from prompt tokens plus max_tokens', async () => {
    const { relay, recorded } = app('none')
    const res = await relay.request('/v1/chat/completions', chat({ model: 'tinfoil/gpt-oss-120b', messages, max_tokens: 100 }))
    expect(res.status).toBe(402)
    const model = prices.models[0]!
    const expected = perRequestPrice(prices, model, { model: model.id, messages, max_tokens: 100 })
    expect(recorded.offers[0]!.chargeAmount).toBe(expected.amount)
    expect(expected.amount).toBe(costInBaseUnits(model, 500, BigInt(expected.promptTokens), 100n))
    expect(boundedMaxTokens({ max_tokens: 10_000 }, model)).toBe(512)
    expect(boundedMaxTokens({}, model)).toBe(512)
    expect(boundedMaxTokens({ max_completion_tokens: 7 }, model)).toBe(7)
  })

  it('forwards a paid charge request with max_tokens bounded', async () => {
    const { relay, llm, logs, usage } = app('charge')
    const res = await relay.request('/v1/chat/completions', chat({ model: 'tinfoil/gpt-oss-120b', messages, max_tokens: 9999 }))
    expect(res.status).toBe(200)
    expect(res.headers.get('payment-receipt')).toBe('charge-receipt')
    expect((await res.json()).choices[0].message.content).toBe('Hello from the relay')
    expect(usage).toEqual([{ model: 'tinfoil/gpt-oss-120b', promptTokens: 10, completionTokens: 4 }])
    expect(llm.calls[0]).toMatchObject({ auth: 'Bearer sk-master', body: { model: 'tinfoil/gpt-oss-120b', max_tokens: 512 } })
    expect(JSON.stringify(logs)).not.toContain('Say hello')
  })

  it('meters a session stream per token and credits the unused prepaid amount', async () => {
    const { relay, recorded, llm, logs, usage } = app('session')
    const res = await relay.request('/v1/chat/completions', chat({ model: 'nearai/z-ai/glm-5.3', messages, stream: true }))
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(usage).toEqual([{ model: 'nearai/z-ai/glm-5.3', promptTokens: 10, completionTokens: 4 }])
    const data = [...text.matchAll(/event: message\ndata: (.*)\n/g)].map((m) => m[1]!)
    expect(data.at(-1)).toBe('[DONE]')
    const contents = data.slice(0, -1).map((d) => JSON.parse(d)).flatMap((c) => c.choices.map((x: any) => x.delta.content))
    expect(contents.join('')).toBe('Hello from the relay')
    expect(data.some((d) => d.includes('"usage"'))).toBe(true)
    expect(llm.calls[0]!.body).toMatchObject({ stream: true, stream_options: { include_usage: true }, max_tokens: 256 })
    // exact final cost for usage {10 prompt, 4 completion}: (10*1.8 + 4*5.75)*1.05 = 43.05 -> 44
    const charged = BigInt(JSON.parse(text.match(/event: payment-receipt\ndata: (.*)\n/)![1]!).charged)
    const credited = recorded.credits.reduce((a, b) => a + b, 0n)
    expect(charged - credited).toBe(44n)
    expect(logs.at(-1)).toMatchObject({ intent: 'session', promptTokens: 10, completionTokens: 4, charged: '44' })
  })

  it('treats a bodyless POST as session management', async () => {
    const { relay, recorded } = app('session')
    const res = await relay.request('/v1/chat/completions', { method: 'POST' })
    expect(res.status).toBe(200)
    expect(recorded.offers).toEqual([{}])
  })

  it('credits everything when the upstream fails', async () => {
    const { relay, recorded } = app('session', undefined, fakeLiteLLM({ status: 500 }))
    const res = await relay.request('/v1/chat/completions', chat({ model: 'nearai/z-ai/glm-5.3', messages, stream: true }))
    const text = await res.text()
    expect(text).toContain('upstream_error')
    const charged = BigInt(JSON.parse(text.match(/event: payment-receipt\ndata: (.*)\n/)![1]!).charged)
    expect(recorded.credits.reduce((a, b) => a + b, 0n)).toBe(charged)
  })
})
