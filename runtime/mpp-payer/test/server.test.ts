import { describe, expect, it } from 'vitest'
import { RelayAttestationGate } from '../src/attestation-gate.js'
import { type RelayResult, RelaySessionFailedError } from '../src/relay-client.js'
import { createPayerApp } from '../src/server.js'
import { BudgetUnavailableError } from '../src/shared-budget.js'
import { SpendLimitError } from '../src/spend-guard.js'
import { fakeAttest, fakeVerifierd } from './helpers/fake-relay-attest.js'

function sessionEvents(words: string[], usage = true): AsyncIterable<string> {
  return (async function* () {
    for (const w of words) yield JSON.stringify({ id: 'c1', model: 'tinfoil/gpt-oss-120b', choices: [{ index: 0, delta: { content: w } }] })
    yield JSON.stringify({ id: 'c1', choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })
    if (usage) yield JSON.stringify({ id: 'c1', choices: [], usage: { prompt_tokens: 3, completion_tokens: words.length } })
    yield '[DONE]'
  })()
}

function setup(relayImpl: (body: Record<string, unknown>) => Promise<RelayResult>, verdict = { ok: true }, callerOk = true) {
  const verifier = fakeVerifierd(verdict)
  const gate = new RelayAttestationGate({
    attestUrl: 'https://relay.example/attest',
    verifierdUrl: 'http://v:8088',
    relayOwner: ('0x' + '0a'.repeat(20)) as `0x${string}`,
    intervalSeconds: 900,
    retrySeconds: 0,
    fetchAttest: fakeAttest().fetchAttest,
    fetchVerifier: verifier.fetchVerifier,
  })
  const calls: Record<string, unknown>[] = []
  let pokes = 0
  const app = createPayerApp({
    gate,
    relay: { chat: async (body) => (calls.push(body), relayImpl(body)), sessionsAvailable: () => true },
    models: async () => Response.json({ object: 'list', data: [{ id: 'tinfoil/gpt-oss-120b' }] }),
    callers: { allows: () => callerOk },
    remoteAddress: () => '172.30.0.16',
    onPayment: () => void pokes++,
  })
  return { app, verifier, calls, pokes: () => pokes }
}

const post = (body: unknown) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
const ask = { model: 'tinfoil/gpt-oss-120b', messages: [{ role: 'user', content: 'hi' }] }

describe('payer OpenAI passthrough', () => {
  it('refuses with a clear 503 while relay attestation fails, then recovers after a pass', async () => {
    const { app, verifier, calls } = setup(async () => ({ kind: 'session', events: sessionEvents(['ok']) }), { ok: false })
    const refused = await app.request('/v1/chat/completions', post(ask))
    expect(refused.status).toBe(503)
    const body = await refused.json()
    expect(body.error.type).toBe('relay_attestation_failed')
    expect(body.error.message).toMatch(/relay attestation failed, refusing to send requests/)
    expect(calls).toEqual([])
    verifier.state.ok = true
    const ok = await app.request('/v1/chat/completions', post(ask))
    expect(ok.status).toBe(200)
    expect(calls.length).toBe(1)
  })

  it('streams a paid session as OpenAI SSE ending in [DONE]', async () => {
    const { app } = setup(async () => ({ kind: 'session', events: sessionEvents(['Hel', 'lo']) }))
    const res = await app.request('/v1/chat/completions', post({ ...ask, stream: true }))
    expect(res.headers.get('content-type')).toBe('text/event-stream')
    const frames = (await res.text()).split('\n\n').filter(Boolean)
    expect(frames.at(-1)).toBe('data: [DONE]')
    expect(frames.filter((f) => f === 'data: [DONE]').length).toBe(1)
    const text = frames.slice(0, -1).map((f) => JSON.parse(f.slice(6))).flatMap((c) => c.choices.map((x: any) => x.delta?.content ?? '')).join('')
    expect(text).toBe('Hello')
  })

  it('folds a session stream into a chat.completion for non-streaming callers', async () => {
    const { app } = setup(async () => ({ kind: 'session', events: sessionEvents(['Hel', 'lo']) }))
    const res = await app.request('/v1/chat/completions', post(ask))
    const json = await res.json()
    expect(json).toMatchObject({
      object: 'chat.completion',
      model: 'tinfoil/gpt-oss-120b',
      choices: [{ index: 0, message: { role: 'assistant', content: 'Hello' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 3, completion_tokens: 2 },
    })
  })

  it('passes per-request charge responses and relay refusals through', async () => {
    const charged = setup(async () => ({ kind: 'response', intent: 'charge', paid: true, streamed: false, response: Response.json({ id: 'x', choices: [] }) }))
    expect((await charged.app.request('/v1/chat/completions', post(ask))).status).toBe(200)
    const refused = setup(async () => ({ kind: 'response', intent: 'refused', paid: false, streamed: false, response: Response.json({ error: { type: 'attestation_failed', provider: 'tinfoil' } }, { status: 503 }) }))
    const res = await refused.app.request('/v1/chat/completions', post(ask))
    expect(res.status).toBe(503)
    expect((await res.json()).error.provider).toBe('tinfoil')
  })

  it('maps the spend guard to 429 and reports spend after payments', async () => {
    const { app, pokes } = setup(async () => Promise.reject(new SpendLimitError(10n, 0n)))
    const res = await app.request('/v1/chat/completions', post(ask))
    expect(res.status).toBe(429)
    expect((await res.json()).error.type).toBe('spend_limit_exceeded')
    expect(pokes()).toBeGreaterThan(0)
  })

  it('maps an unavailable shared budget to 503, also when a top-up fails mid-stream', async () => {
    const { app } = setup(async () => Promise.reject(new BudgetUnavailableError('sealed-agent spend budget unreachable')))
    const res = await app.request('/v1/chat/completions', post(ask))
    expect(res.status).toBe(503)
    expect((await res.json()).error.type).toBe('spend_budget_unavailable')
    const midStream = setup(async () => ({
      kind: 'session',
      events: (async function* () {
        yield JSON.stringify({ id: 'c1', choices: [{ index: 0, delta: { content: 'a' } }] })
        throw new BudgetUnavailableError('sealed-agent spend budget answered HTTP 503')
      })(),
    }))
    const streamed = await (await midStream.app.request('/v1/chat/completions', post({ ...ask, stream: true }))).text()
    expect(streamed).toContain('"type":"spend_budget_unavailable"')
    expect(streamed.trimEnd().endsWith('data: [DONE]')).toBe(true)
    const folded = await midStream.app.request('/v1/chat/completions', post(ask))
    expect(folded.status).toBe(503)
  })

  it('rejects callers other than the llm-gateway and malformed bodies', async () => {
    const blocked = setup(async () => ({ kind: 'session', events: sessionEvents([]) }), { ok: true }, false)
    expect((await blocked.app.request('/v1/chat/completions', post(ask))).status).toBe(403)
    expect((await blocked.app.request('/v1/models')).status).toBe(403)
    const { app } = setup(async () => ({ kind: 'session', events: sessionEvents([]) }))
    expect((await app.request('/v1/chat/completions', { method: 'POST', body: '[1]' })).status).toBe(400)
    const huge = await app.request('/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(4 * 1024 * 1024 + 1) })
    expect(huge.status).toBe(413)
    expect((await (await app.request('/v1/models')).json()).data[0].id).toBe('tinfoil/gpt-oss-120b')
  })

  describe('per-request charges (M3)', () => {
    const sse = (chunks: unknown[]) =>
      new Response(chunks.map((c) => `data: ${typeof c === 'string' ? c : JSON.stringify(c)}\n\n`).join(''), { headers: { 'content-type': 'text/event-stream' } })
    const words = [
      { id: 'c2', model: 'tinfoil/gpt-oss-120b', choices: [{ index: 0, delta: { content: 'Pa' } }] },
      { id: 'c2', choices: [{ index: 0, delta: { content: 'id' }, finish_reason: 'stop' }] },
      { id: 'c2', choices: [], usage: { prompt_tokens: 4, completion_tokens: 2 } },
      '[DONE]',
    ]

    it('answers 424 (not retried by LiteLLM or the OpenAI SDKs) when the relay failed after taking a charge', async () => {
      const { app } = setup(async () => ({
        kind: 'response',
        intent: 'charge',
        paid: true,
        streamed: false,
        response: Response.json({ error: { type: 'upstream_error' } }, { status: 502, headers: { 'payment-receipt': 'r' } }),
      }))
      const res = await app.request('/v1/chat/completions', post(ask))
      expect(res.status).toBe(424)
      expect((await res.json()).error).toMatchObject({ type: 'relay_failed_after_payment', relay_status: 502 })
    })

    it('passes an uncharged relay failure through with its status (a retry costs nothing)', async () => {
      const { app } = setup(async () => ({
        kind: 'response',
        intent: 'refused',
        paid: false,
        streamed: false,
        response: Response.json({ error: { type: 'upstream_error', charged: false } }, { status: 503 }),
      }))
      const res = await app.request('/v1/chat/completions', post(ask))
      expect(res.status).toBe(503)
      expect((await res.json()).error.charged).toBe(false)
    })

    it('folds a streamed charge back into one chat.completion for a non-stream caller, and passes it through for a stream caller', async () => {
      const charged = () => setup(async () => ({ kind: 'response', intent: 'charge', paid: true, streamed: true, response: sse(words) }))
      const folded = await charged().app.request('/v1/chat/completions', post(ask))
      expect(await folded.json()).toMatchObject({ object: 'chat.completion', choices: [{ message: { content: 'Paid' } }], usage: { prompt_tokens: 4 } })
      const streamed = await charged().app.request('/v1/chat/completions', post({ ...ask, stream: true }))
      expect(streamed.headers.get('content-type')).toBe('text/event-stream')
      expect(await streamed.text()).toContain('data: [DONE]')
      const broken = setup(async () => ({ kind: 'response', intent: 'charge', paid: true, streamed: true, response: sse([words[0], { error: { message: 'provider dropped' } }]) }))
      expect((await broken.app.request('/v1/chat/completions', post(ask))).status).toBe(424)
    })

    it('answers 502 relay_session_failed when a session request failed after it was sent', async () => {
      const { app } = setup(async () => Promise.reject(new RelaySessionFailedError('sent', { cause: new Error('reset') })))
      const res = await app.request('/v1/chat/completions', post(ask))
      expect(res.status).toBe(502)
      expect((await res.json()).error.type).toBe('relay_session_failed')
    })
  })
})
