import { EventSourceParserStream } from 'eventsource-parser/stream'
import type { FetchLike } from './providers/types.js'

/** The relay's LiteLLM (OpenAI-compatible); the only place the front sends prompts. */
export class Upstream {
  constructor(
    private readonly options: { baseURL: string; apiKey: string; fetch?: FetchLike; timeoutMs?: number },
  ) {}

  chatCompletions(body: Record<string, unknown>, signal?: AbortSignal): Promise<Response> {
    const fetchImpl = this.options.fetch ?? fetch
    const timeout = AbortSignal.timeout(this.options.timeoutMs ?? 600_000)
    return fetchImpl(`${this.options.baseURL.replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.options.apiKey}` },
      body: JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    })
  }
}

/** Yields the `data` field of every SSE event in an OpenAI-style stream. */
export async function* sseData(response: Response): AsyncGenerator<string> {
  if (!response.body) return
  const events = response.body.pipeThrough(new TextDecoderStream()).pipeThrough(new EventSourceParserStream())
  const reader = events.getReader()
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return
      if (value.data !== undefined) yield value.data
    }
  } finally {
    reader.releaseLock()
    await response.body.cancel().catch(() => {})
  }
}

export type ChatChunk = {
  id?: string
  choices?: { delta?: { content?: string | null; reasoning_content?: string | null; tool_calls?: unknown } }[]
  usage?: { prompt_tokens?: number; completion_tokens?: number } | null
}

/** Text delivered by one streamed chunk (content, reasoning and tool-call arguments). */
export function chunkText(chunk: ChatChunk): string {
  let text = ''
  for (const choice of chunk.choices ?? []) {
    const delta = choice.delta ?? {}
    if (typeof delta.content === 'string') text += delta.content
    if (typeof delta.reasoning_content === 'string') text += delta.reasoning_content
    if (delta.tool_calls !== undefined) text += JSON.stringify(delta.tool_calls)
  }
  return text
}
