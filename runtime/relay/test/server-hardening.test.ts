import { describe, expect, it } from 'vitest'
import { ChatRequestError, sanitizeChatRequest } from '../src/chat-request.js'
import type { Payments, PaymentResult } from '../src/payments.js'
import { type PriceTable, parsePriceTable } from '../src/prices.js'
import type { ProviderStatus } from '../src/providers/types.js'
import { RateLimiter, clientKey } from '../src/rate-limit.js'
import { createRelayApp, perRequestPrice } from '../src/server.js'
import { estimatePromptTokens } from '../src/tokens.js'
import { Upstream } from '../src/upstream.js'
import { stripUsageChunks } from '../src/usage.js'
import { fakeLiteLLM } from './helpers/fake-litellm.js'

const prices: PriceTable = parsePriceTable(
  {
    currency: '0x20c0000000000000000000000000000000000000',
    decimals: 6,
    default_max_tokens: 256,
    models: [
      { id: 'phala/openai/gpt-oss-120b', provider: 'phala', upstream_model: 'openai/gpt-oss-120b', input_per_1m: 150000, output_per_1m: 600000, max_output_tokens: 512 },
      { id: 'nearai/z-ai/glm-5.3', provider: 'nearai', upstream_model: 'z-ai/glm-5.3', input_per_1m: 1800000, output_per_1m: 5750000 },
    ],
  },
  500,
)

const messages = [{ role: 'user', content: 'Say hello' }]
const chat = (body: unknown, headers: Record<string, string> = {}) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify(body),
})

function setup(
  options: {
    intent?: 'none' | 'charge'
    verified?: () => boolean
    onRefresh?: () => void
    limiter?: RateLimiter
    maxBodyBytes?: number
    llm?: ReturnType<typeof fakeLiteLLM>
  } = {},
) {
  const offers: unknown[] = []
  const refreshed: string[] = []
  const verified = options.verified ?? (() => true)
  const status = (provider: string): ProviderStatus => ({
    provider: provider as ProviderStatus['provider'],
    enabled: true,
    verified: verified(),
    detail: verified() ? 'attestation verified' : 'attestation lapsed',
  })
  const payments: Payments = {
    sessionsEnabled: false,
    preflightCharge: async () => ((options.intent ?? 'charge') === 'none' ? { kind: 'none' } : { kind: 'valid' }),
    async handle(_request, o): Promise<PaymentResult> {
      offers.push(o)
      if ((options.intent ?? 'charge') === 'none') return { status: 402, challenge: new Response('pay', { status: 402 }) }
      return { status: 200, intent: 'charge', withReceipt: (r) => r as Response }
    },
    credit: async () => 'credited',
  }
  const llm = options.llm ?? fakeLiteLLM()
  const relay = createRelayApp({
    prices,
    gate: {
      allows: (p: string) => status(p).verified,
      status,
      all: () => [],
      refresh: async (p: string) => {
        refreshed.push(p)
        options.onRefresh?.()
      },
    } as never,
    payments,
    upstream: new Upstream({ baseURL: 'http://litellm:4000/v1', apiKey: 'sk-master', fetch: llm.fetch }),
    batchTokens: 8,
    maxBodyBytes: options.maxBodyBytes,
    unpaidLimiter: options.limiter,
    clientKey: (c) => c.req.header('x-test-client') ?? 'anon',
  })
  return { relay, offers, llm, refreshed }
}

describe('relay request hardening', () => {
  it('forwards only allowlisted chat parameters to LiteLLM', async () => {
    const { relay, llm } = setup()
    const res = await relay.request(
      '/v1/chat/completions',
      chat({
        model: 'phala/openai/gpt-oss-120b',
        messages,
        temperature: 0.2,
        tools: [{ type: 'function', function: { name: 'f', parameters: {} } }],
        fallbacks: ['nearai/z-ai/glm-5.3'],
        context_window_fallbacks: [{ 'phala/openai/gpt-oss-120b': ['nearai/z-ai/glm-5.3'] }],
        mock_response: 'free tokens',
        mock_testing_fallbacks: true,
        api_key: 'sk-attacker',
        api_base: 'http://169.254.169.254/latest',
        base_url: 'http://evil.example',
        metadata: { tags: ['x'] },
        user_config: { model_list: [] },
        num_retries: 50,
      }),
    )
    expect(res.status).toBe(200)
    const sent = llm.calls[0]!.body
    expect(Object.keys(sent).sort()).toEqual(['max_tokens', 'messages', 'model', 'temperature', 'tools'])
    expect(llm.calls[0]!.auth).toBe('Bearer sk-master')
  })

  it('rejects n > 1, which one per-request charge does not cover', async () => {
    const { relay, offers, llm } = setup()
    const res = await relay.request('/v1/chat/completions', chat({ model: 'phala/openai/gpt-oss-120b', messages, n: 64 }))
    expect(res.status).toBe(400)
    expect((await res.json()).error.message).toMatch(/n must be 1/)
    expect(offers).toEqual([])
    expect(llm.calls).toEqual([])
    expect((await relay.request('/v1/chat/completions', chat({ model: 'phala/openai/gpt-oss-120b', messages, n: 1 }))).status).toBe(200)
  })

  it('rejects content parts it cannot price and malformed parameters', async () => {
    const { relay } = setup()
    const image = await relay.request(
      '/v1/chat/completions',
      chat({ model: 'phala/openai/gpt-oss-120b', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'https://x/y.png' } }] }] }),
    )
    expect(image.status).toBe(400)
    expect((await image.json()).error.type).toBe('unsupported_content')
    for (const bad of [{ messages: [] }, { messages, tools: 'x' }, { messages, temperature: 9 }, { messages, stop: ['a', 'b', 'c', 'd', 'e'] }])
      expect(() => sanitizeChatRequest(bad)).toThrow(ChatRequestError)
  })

  it('prices every prompt-bearing field it forwards', () => {
    const base = { messages }
    const schema = { type: 'json_schema', json_schema: { name: 's', schema: { description: 'x'.repeat(3000) } } }
    expect(estimatePromptTokens({ ...base, response_format: schema })).toBeGreaterThan(estimatePromptTokens(base) + 900)
    expect(estimatePromptTokens({ ...base, functions: [{ name: 'f', description: 'y'.repeat(900) }] })).toBeGreaterThan(estimatePromptTokens(base) + 290)
    const toolMessage = [{ role: 'tool', tool_call_id: 'call_' + 'z'.repeat(300), content: 'r' }]
    expect(estimatePromptTokens({ messages: toolMessage })).toBeGreaterThan(estimatePromptTokens({ messages: [{ role: 'tool', content: 'r' }] }) + 90)
    const model = prices.models[0]!
    expect(perRequestPrice(prices, model, { ...base, response_format: schema }).amount).toBeGreaterThan(perRequestPrice(prices, model, base).amount)
    // Dropped fields are not priced (and never reach the provider).
    expect(estimatePromptTokens({ ...base, metadata: { big: 'q'.repeat(9000) } })).toBe(estimatePromptTokens(base))
  })

  it('refuses oversized bodies before reading them', async () => {
    const { relay, offers } = setup({ maxBodyBytes: 1024 })
    const big = JSON.stringify({ model: 'phala/openai/gpt-oss-120b', messages: [{ role: 'user', content: 'x'.repeat(4096) }] })
    const declared = await relay.request('/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(big.length) }, body: big })
    expect(declared.status).toBe(413)
    const encoder = new TextEncoder()
    const streamed = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < 8; i++) c.enqueue(encoder.encode('x'.repeat(512)))
        c.close()
      },
    })
    const chunked = await relay.request(new Request('http://relay/v1/chat/completions', { method: 'POST', body: streamed, duplex: 'half' } as RequestInit))
    expect(chunked.status).toBe(413)
    expect(offers).toEqual([])
  })

  it('rate-limits unpaid requests per client but never paid retries', async () => {
    const { relay } = setup({ intent: 'none', limiter: new RateLimiter({ perMinute: 2, now: () => 0 }) })
    const body = { model: 'phala/openai/gpt-oss-120b', messages }
    expect((await relay.request('/v1/chat/completions', chat(body, { 'x-test-client': 'a' }))).status).toBe(402)
    expect((await relay.request('/v1/chat/completions', chat(body, { 'x-test-client': 'a' }))).status).toBe(402)
    const limited = await relay.request('/v1/chat/completions', chat(body, { 'x-test-client': 'a' }))
    expect(limited.status).toBe(429)
    expect(limited.headers.get('retry-after')).toBe('10')
    expect((await relay.request('/v1/chat/completions', chat(body, { 'x-test-client': 'b' }))).status).toBe(402)
    expect((await relay.request('/v1/chat/completions', chat(body, { 'x-test-client': 'a', authorization: 'Payment xyz' }))).status).toBe(402)
  })

  it('re-reads the provider status before a paid request settles and refuses if it lapsed', async () => {
    let verified = true
    // The refresh flips the provider to unverified, as a sidecar would after a failed re-attestation.
    const { relay, refreshed, offers, llm } = setup({ verified: () => verified, onRefresh: () => void (verified = false) })
    const body = { model: 'phala/openai/gpt-oss-120b', messages }
    expect((await relay.request('/v1/chat/completions', chat(body))).status).toBe(200)
    expect(refreshed).toEqual([])
    verified = true
    const res = await relay.request('/v1/chat/completions', chat(body, { authorization: 'Payment cred' }))
    expect(res.status).toBe(503)
    expect((await res.json()).error.message).toMatch(/attestation lapsed/)
    expect(refreshed).toEqual(['phala'])
    expect(offers.length).toBe(1)
    expect(llm.calls.length).toBe(1)
  })

  it('asks for usage on charge streams and strips the usage chunk the client did not request', async () => {
    const llm = fakeLiteLLM()
    const { relay } = setup({ llm })
    const plain = await relay.request('/v1/chat/completions', chat({ model: 'phala/openai/gpt-oss-120b', messages, stream: true }))
    const text = await plain.text()
    expect(llm.calls[0]!.body).toMatchObject({ stream: true, stream_options: { include_usage: true } })
    expect(text).toContain('Hello')
    expect(text).not.toContain('"usage"')
    expect(text).toContain('data: [DONE]')
    const withUsage = await relay.request(
      '/v1/chat/completions',
      chat({ model: 'phala/openai/gpt-oss-120b', messages, stream: true, stream_options: { include_usage: true } }),
    )
    expect(await withUsage.text()).toContain('"usage"')
  })

  it('reports streamed charge usage to the agent', async () => {
    const usage: unknown[] = []
    const llm = fakeLiteLLM({ usage: { prompt_tokens: 7, completion_tokens: 4 } })
    const relay = createRelayApp({
      prices,
      gate: { allows: () => true, status: (p: string) => ({ provider: p, enabled: true, verified: true, detail: 'ok' }), all: () => [] } as never,
      payments: {
        sessionsEnabled: false,
        preflightCharge: async () => ({ kind: 'valid' }),
        handle: async () => ({ status: 200, intent: 'charge', withReceipt: (r) => r as Response }),
        credit: async () => 'credited',
      },
      upstream: new Upstream({ baseURL: 'http://litellm/v1', apiKey: 'k', fetch: llm.fetch }),
      batchTokens: 8,
      onUsage: (e) => usage.push(e),
    })
    await (await relay.request('/v1/chat/completions', chat({ model: 'phala/openai/gpt-oss-120b', messages, stream: true }))).text()
    expect(usage).toEqual([{ model: 'phala/openai/gpt-oss-120b', promptTokens: 7, completionTokens: 4 }])
  })

  it('strips only usage-only SSE events', async () => {
    const sse = 'data: {"choices":[{"delta":{"content":"a"}}]}\n\ndata: {"choices":[],"usage":{"prompt_tokens":1}}\r\n\r\ndata: [DONE]\n\n'
    const out = await stripUsageChunks(new Response(sse, { headers: { 'content-type': 'text/event-stream' } })).text()
    expect(out).toBe('data: {"choices":[{"delta":{"content":"a"}}]}\n\ndata: [DONE]\n\n')
    const json = new Response('{"usage":{}}', { headers: { 'content-type': 'application/json' } })
    expect(await stripUsageChunks(json).text()).toBe('{"usage":{}}')
  })

  it('keys clients by the X-Forwarded-For hop only behind the trusted proxy', () => {
    expect(clientKey('::ffff:172.30.0.4', '203.0.113.9, 10.0.0.1', ['172.30.0.4'])).toBe('203.0.113.9')
    expect(clientKey('198.51.100.7', '203.0.113.9', ['172.30.0.4'])).toBe('198.51.100.7')
    expect(clientKey(undefined, null, [])).toBe('unknown')
    const limiter = new RateLimiter({ perMinute: 60, burst: 1, maxKeys: 2, now: () => 0 })
    expect(limiter.take('a')).toBe(true)
    expect(limiter.take('a')).toBe(false)
    limiter.take('b')
    limiter.take('c')
    // "a" was evicted as the stalest key, so it starts with a full bucket again.
    expect(limiter.take('a')).toBe(true)
  })
})
