/**
 * Deterministic, tokenizer-free token estimates. The per-request charge must be
 * computed identically for the 402 challenge and the paid retry of the same body,
 * so this never calls out to a tokenizer service. It errs high: about 3 UTF-8 bytes
 * per token (typical English text is about 4) plus a fixed overhead per message.
 */
const BYTES_PER_TOKEN = 3
const MESSAGE_OVERHEAD_TOKENS = 4
const REQUEST_OVERHEAD_TOKENS = 3

function textOf(content: unknown): string {
  if (typeof content === 'string') return content
  if (Array.isArray(content))
    return content
      .map((part) => {
        if (part && typeof part === 'object' && 'text' in part && typeof part.text === 'string') return part.text
        return JSON.stringify(part ?? '')
      })
      .join('')
  if (content == null) return ''
  return JSON.stringify(content)
}

function tokensForText(text: string): number {
  return Math.ceil(Buffer.byteLength(text, 'utf8') / BYTES_PER_TOKEN)
}

export function estimatePromptTokens(body: { messages?: unknown; tools?: unknown }): number {
  let total = REQUEST_OVERHEAD_TOKENS
  const messages = Array.isArray(body.messages) ? body.messages : []
  for (const message of messages) {
    total += MESSAGE_OVERHEAD_TOKENS
    if (message && typeof message === 'object') {
      const m = message as Record<string, unknown>
      total += tokensForText(textOf(m.content))
      if (typeof m.name === 'string') total += tokensForText(m.name)
      if (m.tool_calls !== undefined) total += tokensForText(JSON.stringify(m.tool_calls))
    }
  }
  if (body.tools !== undefined) total += tokensForText(JSON.stringify(body.tools))
  return total
}

/** Rough completion-token count for one streamed delta; at least 1 per non-empty chunk. */
export function estimateDeltaTokens(text: string): number {
  if (!text) return 0
  return Math.max(1, Math.ceil(Buffer.byteLength(text, 'utf8') / 4))
}
