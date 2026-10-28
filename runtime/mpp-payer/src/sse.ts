import { EventSourceParserStream } from 'eventsource-parser/stream'

/** Yields the `data` field of every SSE event in an OpenAI-style stream. */
export async function* sseData(response: Response): AsyncGenerator<string> {
  if (!response.body) return
  const reader = response.body.pipeThrough(new TextDecoderStream()).pipeThrough(new EventSourceParserStream()).getReader()
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return
      if (value.data !== undefined) yield value.data
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
}
