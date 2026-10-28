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

function isUsageOnlyEvent(event: string): boolean {
  const data = event
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim())
    .join('\n')
  if (!data.includes('"usage"')) return false
  try {
    const chunk = JSON.parse(data) as { choices?: unknown; usage?: unknown }
    return Array.isArray(chunk.choices) && chunk.choices.length === 0 && !!chunk.usage
  } catch {
    return false
  }
}

/**
 * Drops the trailing usage-only chunk (`choices: []` with `usage`) from an OpenAI SSE stream.
 * The relay always asks its upstream for usage on streams; a client that did not ask for it
 * gets the stream it requested.
 */
export function stripUsageChunks(response: Response): Response {
  if (!response.body || !(response.headers.get('content-type') ?? '').includes('text/event-stream')) return response
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()
  let pending = ''
  const emitComplete = (controller: TransformStreamDefaultController<Uint8Array>) => {
    pending = pending.replace(/\r\n/g, '\n')
    let end = pending.indexOf('\n\n')
    while (end >= 0) {
      const event = pending.slice(0, end + 2)
      pending = pending.slice(end + 2)
      if (!isUsageOnlyEvent(event)) controller.enqueue(encoder.encode(event))
      end = pending.indexOf('\n\n')
    }
  }
  const filter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      pending += decoder.decode(chunk, { stream: true })
      emitComplete(controller)
    },
    flush(controller) {
      pending += decoder.decode()
      emitComplete(controller)
      if (pending && !isUsageOnlyEvent(pending)) controller.enqueue(encoder.encode(pending))
    },
  })
  return new Response(response.body.pipeThrough(filter), { status: response.status, headers: response.headers })
}
