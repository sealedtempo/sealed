import type { FetchLike } from './providers/types.js'

export type Usage = { prompt_tokens?: number; completion_tokens?: number }

export type UsageEvent = { model: string; promptTokens: number; completionTokens: number }

/**
 * Posts token counts to the relay deployment's own sealed-agent (`metering: tokens/callback`,
 * INTERFACES section 11). Content-free: model and counts only. Failures are swallowed; the
 * relay's MPP receipts remain the payment record.
 */
export function agentUsageSink(url: string, fetchImpl: FetchLike = fetch): (event: UsageEvent) => void {
  return (event) => {
    const quantity = event.promptTokens + event.completionTokens
    if (quantity <= 0) return
    void fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        app: 'inference-relay',
        unit: 'tokens',
        quantity,
        meta: { model: event.model, prompt_tokens: event.promptTokens, completion_tokens: event.completionTokens },
      }),
      signal: AbortSignal.timeout(5_000),
    }).catch(() => {})
  }
}

function readUsage(value: unknown): Usage | undefined {
  if (!value || typeof value !== 'object') return undefined
  const usage = (value as { usage?: unknown }).usage
  return usage && typeof usage === 'object' ? (usage as Usage) : undefined
}

/**
 * Passes an upstream response through unchanged while reading its `usage` (JSON body or the
 * usage chunk of an SSE stream) and reporting it once the body has been fully delivered.
 */
export function tapUsage(response: Response, onUsage: (usage: Usage | undefined) => void): Response {
  if (!response.body) {
    onUsage(undefined)
    return response
  }
  const isStream = (response.headers.get('content-type') ?? '').includes('text/event-stream')
  const decoder = new TextDecoder()
  let text = ''
  let found: Usage | undefined
  let reported = false
  const report = () => {
    if (reported) return
    reported = true
    if (!isStream) {
      try {
        found = readUsage(JSON.parse(text))
      } catch {}
    }
    onUsage(found)
  }
  const tap = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      controller.enqueue(chunk)
      text += decoder.decode(chunk, { stream: true })
      if (!isStream) return
      let newline = text.indexOf('\n')
      while (newline >= 0) {
        const line = text.slice(0, newline).trim()
        text = text.slice(newline + 1)
        if (line.startsWith('data:')) {
          const data = line.slice(5).trim()
          if (data.includes('"usage"')) {
            try {
              found = readUsage(JSON.parse(data)) ?? found
            } catch {}
          }
        }
        newline = text.indexOf('\n')
      }
    },
    flush() {
      report()
    },
  })
  return new Response(response.body.pipeThrough(tap), { status: response.status, headers: response.headers })
}
