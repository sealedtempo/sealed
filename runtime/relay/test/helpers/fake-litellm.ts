/** A stand-in for the relay's LiteLLM: records requests, answers JSON or an OpenAI SSE stream with usage. */
export function fakeLiteLLM(options: { words?: string[]; usage?: { prompt_tokens: number; completion_tokens: number } | null; status?: number } = {}) {
  const calls: { body: Record<string, unknown>; auth: string | null }[] = []
  const words = options.words ?? ['Hello', ' from', ' the', ' relay']
  const fetchImpl = async (_input: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
    calls.push({ body, auth: new Headers(init?.headers).get('authorization') })
    if (options.status && options.status !== 200) return Response.json({ error: { message: 'upstream failed' } }, { status: options.status })
    if (body.stream !== true)
      return Response.json({
        id: 'chatcmpl-1',
        object: 'chat.completion',
        model: body.model,
        choices: [{ index: 0, message: { role: 'assistant', content: words.join('') }, finish_reason: 'stop' }],
        usage: options.usage ?? { prompt_tokens: 10, completion_tokens: words.length },
      })
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const w of words)
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ id: 'chatcmpl-1', object: 'chat.completion.chunk', model: body.model, choices: [{ index: 0, delta: { content: w } }] })}\n\n`))
        if (options.usage !== null)
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ id: 'chatcmpl-1', object: 'chat.completion.chunk', choices: [], usage: options.usage ?? { prompt_tokens: 10, completion_tokens: words.length } })}\n\n`))
        controller.enqueue(encoder.encode('data: [DONE]\n\n'))
        controller.close()
      },
    })
    return new Response(stream, { headers: { 'content-type': 'text/event-stream' } })
  }
  return { calls, fetch: fetchImpl }
}
