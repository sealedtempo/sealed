import type { ModelPrice } from './prices.js'

/**
 * The OpenAI chat-completions parameters the relay forwards to its LiteLLM. Everything else in a
 * client body is dropped: LiteLLM honours client-side routing and credential fields (fallbacks,
 * context_window_fallbacks, mock_*, api_key, api_base, base_url, metadata, user_config, ...),
 * which would let a paying client pick another (pricier or refused) model, fake responses or
 * point LiteLLM at arbitrary hosts. Prompt-bearing fields that are kept are all priced.
 */
const FORWARDED = new Set([
  'messages',
  'tools',
  'tool_choice',
  'parallel_tool_calls',
  'functions',
  'function_call',
  'response_format',
  'temperature',
  'top_p',
  'stop',
  'seed',
  'presence_penalty',
  'frequency_penalty',
  'logit_bias',
  'logprobs',
  'top_logprobs',
  'reasoning_effort',
])

/** Content part types the price estimate covers; images, audio and files are billed by the provider in ways we cannot price. */
const TEXT_PARTS = new Set(['text', 'input_text', 'refusal'])

export class ChatRequestError extends Error {
  constructor(
    readonly type: string,
    message: string,
  ) {
    super(message)
    this.name = 'ChatRequestError'
  }
}

export type SanitizedChat = {
  /** Body for LiteLLM, without model, max_tokens or stream settings (the caller sets those). */
  body: Record<string, unknown>
  stream: boolean
  /** The client asked for the trailing usage chunk of a stream. */
  wantsUsage: boolean
}

function fail(message: string, type = 'invalid_request'): never {
  throw new ChatRequestError(type, message)
}

function checkNumber(body: Record<string, unknown>, name: string, min: number, max: number): void {
  const v = body[name]
  if (v === undefined || v === null) return
  if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max) fail(`${name} must be a number in [${min}, ${max}]`)
}

function checkMessages(messages: unknown): void {
  if (!Array.isArray(messages) || messages.length === 0) fail('messages must be a non-empty array')
  for (const [i, message] of messages.entries()) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) fail(`messages[${i}] must be an object`)
    const content = (message as { content?: unknown }).content
    if (!Array.isArray(content)) continue
    for (const part of content) {
      const type = part && typeof part === 'object' ? (part as { type?: unknown }).type : undefined
      if (typeof type !== 'string' || !TEXT_PARTS.has(type))
        fail(`messages[${i}] has a ${String(type)} content part; the relay prices text only`, 'unsupported_content')
    }
  }
}

/**
 * Validates a client chat request and keeps only the forwarded parameters. `n` must be 1 (a
 * per-request charge covers one completion), and stream_options is rebuilt by the relay.
 */
export function sanitizeChatRequest(body: Record<string, unknown>): SanitizedChat {
  checkMessages(body.messages)
  if (body.n !== undefined && body.n !== null && body.n !== 1) fail('n must be 1: the relay prices and returns one completion per request')
  if (body.stream !== undefined && body.stream !== null && typeof body.stream !== 'boolean') fail('stream must be a boolean')
  for (const name of ['tools', 'functions'] as const)
    if (body[name] !== undefined && body[name] !== null && !Array.isArray(body[name])) fail(`${name} must be an array`)
  if (body.response_format !== undefined && body.response_format !== null && (typeof body.response_format !== 'object' || Array.isArray(body.response_format)))
    fail('response_format must be an object')
  if (body.stop !== undefined && body.stop !== null) {
    const stops = Array.isArray(body.stop) ? body.stop : [body.stop]
    if (stops.length > 4 || stops.some((s) => typeof s !== 'string')) fail('stop must be a string or up to 4 strings')
  }
  checkNumber(body, 'temperature', 0, 2)
  checkNumber(body, 'top_p', 0, 1)
  checkNumber(body, 'presence_penalty', -2, 2)
  checkNumber(body, 'frequency_penalty', -2, 2)
  checkNumber(body, 'top_logprobs', 0, 20)
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) if (FORWARDED.has(key) && value !== undefined && value !== null) out[key] = value
  const stream = body.stream === true
  const options = body.stream_options
  const wantsUsage = stream && !!options && typeof options === 'object' && (options as { include_usage?: unknown }).include_usage === true
  return { body: out, stream, wantsUsage }
}

/** The LiteLLM body: sanitized parameters, the relay's model id and the bounded max_tokens. */
export function upstreamBody(
  sanitized: SanitizedChat,
  model: ModelPrice,
  maxTokens: number,
  original: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...sanitized.body, model: model.id, max_tokens: maxTokens }
  if ('max_completion_tokens' in original) out.max_completion_tokens = maxTokens
  // Usage is always requested on streams: it meters sessions and the relay's token callback.
  if (sanitized.stream) Object.assign(out, { stream: true, stream_options: { include_usage: true } })
  return out
}
