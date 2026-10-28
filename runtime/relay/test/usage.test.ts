import { describe, expect, it } from 'vitest'
import { agentUsageSink, tapUsage } from '../src/usage.js'

describe('usage metering', () => {
  it('reads usage from a JSON body without altering it', async () => {
    const seen: unknown[] = []
    const res = tapUsage(Response.json({ id: 'x', usage: { prompt_tokens: 5, completion_tokens: 7 } }), (u) => seen.push(u))
    expect(await res.json()).toEqual({ id: 'x', usage: { prompt_tokens: 5, completion_tokens: 7 } })
    expect(seen).toEqual([{ prompt_tokens: 5, completion_tokens: 7 }])
  })

  it('reads the usage chunk of an SSE stream split across reads', async () => {
    const seen: unknown[] = []
    const enc = new TextEncoder()
    const body = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: {"choices":[],"us'))
        c.enqueue(enc.encode('age":{"prompt_tokens":2,"completion_tokens":1}}\n\ndata: [DONE]\n\n'))
        c.close()
      },
    })
    const res = tapUsage(new Response(body, { headers: { 'content-type': 'text/event-stream' } }), (u) => seen.push(u))
    expect(await res.text()).toContain('[DONE]')
    expect(seen).toEqual([{ prompt_tokens: 2, completion_tokens: 1 }])
  })

  it('posts content-free token events to sealed-agent', async () => {
    const posts: any[] = []
    const sink = agentUsageSink('http://sealed-agent:7070/v1/usage-events', async (url, init) => {
      posts.push({ url, body: JSON.parse(String(init?.body)) })
      return new Response(null, { status: 202 })
    })
    sink({ model: 'phala/openai/gpt-oss-120b', promptTokens: 3, completionTokens: 4 })
    sink({ model: 'x', promptTokens: 0, completionTokens: 0 })
    await new Promise((r) => setTimeout(r, 10))
    expect(posts).toEqual([
      {
        url: 'http://sealed-agent:7070/v1/usage-events',
        body: { app: 'inference-relay', unit: 'tokens', quantity: 7, meta: { model: 'phala/openai/gpt-oss-120b', prompt_tokens: 3, completion_tokens: 4 } },
      },
    ])
  })
})
