import { randomUUID } from 'node:crypto'
import { type Context, Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { ChatRequestError, sanitizeChatRequest, upstreamBody as buildUpstreamBody } from './chat-request.js'
import { SessionMeter } from './metering.js'
import type { Payments } from './payments.js'
import {
  DEFAULT_MODEL_ALIAS,
  type ModelPrice,
  type PriceTable,
  costInBaseUnits,
  findModel,
  formatUnits,
  relayPricePer1M,
} from './prices.js'
import type { ProviderGate } from './providers/gate.js'
import type { RateLimiter } from './rate-limit.js'
import { estimatePromptTokens } from './tokens.js'
import { type ChatChunk, type Upstream, sseData } from './upstream.js'
import { type UsageEvent, stripUsageChunks, tapUsage } from './usage.js'

/** Large enough for the biggest priced context (128k tokens of text plus tools) with JSON overhead. */
export const DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024

/**
 * A per-request charge is settled only after the upstream's first byte. The payer's signed
 * transaction expires at its validBefore (mppx: 25 s after signing), and the broadcast needs
 * time to be included, so the first byte must arrive this long before validBefore.
 */
export const SETTLE_MARGIN_MS = 6_000
/** Without a validBefore, the longest the relay waits for the first byte before refusing. */
export const MAX_FIRST_BYTE_WAIT_MS = 20_000

export type RelayDeps = {
  prices: PriceTable
  gate: Pick<ProviderGate, 'allows' | 'status' | 'all'> & Partial<Pick<ProviderGate, 'refresh'>>
  upstream: Upstream
  payments: Payments
  batchTokens: number
  /** Content-free request log: model, provider, intent, token counts and amounts only. */
  log?: (event: Record<string, unknown>) => void
  /** Token metering callback to the relay deployment's sealed-agent. */
  onUsage?: (event: UsageEvent) => void
  /** Request bodies above this are refused before they are read in full. */
  maxBodyBytes?: number
  /** Limits requests that carry no payment credential, per client. */
  unpaidLimiter?: Pick<RateLimiter, 'take'>
  clientKey?: (c: Context) => string
  now?: () => number
}

/** The same request without its payment credential (to answer it with a fresh challenge). */
function withoutCredential(request: Request, body: string): Request {
  const headers = new Headers(request.headers)
  headers.delete('authorization')
  headers.delete('payment-authorization')
  return new Request(request.url, { method: request.method, headers, body })
}

function hasPaymentCredential(request: Request): boolean {
  return /^Payment\s+/i.test(request.headers.get('authorization') ?? '')
}

/** Reading the upstream's SSE stream failed (a reset or a timeout), as opposed to the meter's own errors. */
class UpstreamStreamError extends Error {}

async function* readUpstream(response: Response): AsyncGenerator<string> {
  try {
    yield* sseData(response)
  } catch (error) {
    throw new UpstreamStreamError('the upstream stream failed', { cause: error })
  }
}

type ChatBody = Record<string, unknown> & { model?: unknown; max_tokens?: unknown; max_completion_tokens?: unknown; stream?: unknown }

function errorResponse(status: number, type: string, message: string, extra: Record<string, unknown> = {}): Response {
  return Response.json({ error: { type, message, ...extra } }, { status })
}

/** max_tokens bounded by the model's limit; the relay always sets it so a request's cost is bounded. */
export function boundedMaxTokens(body: ChatBody, model: ModelPrice): number {
  const requested = body.max_completion_tokens ?? body.max_tokens
  if (typeof requested === 'number' && Number.isSafeInteger(requested) && requested > 0)
    return Math.min(requested, model.maxOutputTokens)
  return model.maxOutputTokens
}

/** Per-request (charge intent) price: estimated prompt tokens plus the full max_tokens budget. */
export function perRequestPrice(prices: PriceTable, model: ModelPrice, body: ChatBody): { amount: bigint; promptTokens: number; maxTokens: number } {
  const promptTokens = estimatePromptTokens(body)
  const maxTokens = boundedMaxTokens(body, model)
  return { amount: costInBaseUnits(model, prices.markupBps, BigInt(promptTokens), BigInt(maxTokens)), promptTokens, maxTokens }
}

export function modelsDocument(prices: PriceTable, gate: RelayDeps['gate']) {
  const defaultModel = findModel(prices, DEFAULT_MODEL_ALIAS, (m) => gate.allows(m.provider))
  return {
    object: 'list',
    default_model: defaultModel?.id,
    data: prices.models.map((m) => {
      const status = gate.status(m.provider)
      return {
        id: m.id,
        object: 'model',
        owned_by: m.provider,
        sealed: {
          provider: m.provider,
          available: status.enabled && status.verified,
          attested: status.verified,
          max_output_tokens: m.maxOutputTokens,
          price: {
            currency: prices.currency,
            decimals: prices.decimals,
            unit: 'base units per 1M tokens',
            markup_bps: prices.markupBps,
            input_per_1m: relayPricePer1M(m.inputPer1M, prices.markupBps),
            output_per_1m: relayPricePer1M(m.outputPer1M, prices.markupBps),
            list_input_per_1m: m.inputPer1M.toString(),
            list_output_per_1m: m.outputPer1M.toString(),
          },
        },
      }
    }),
  }
}

export function createRelayApp(deps: RelayDeps): Hono {
  const app = new Hono()
  const log = deps.log ?? (() => {})
  const onUsage = deps.onUsage ?? (() => {})

  const now = deps.now ?? Date.now

  /**
   * Per-request charge: the credential was validated (not broadcast). The upstream is called
   * first; the charge is settled only when the upstream answered 2xx and produced its first
   * byte. An upstream that fails or stays silent before that costs the payer nothing: the
   * answer carries no payment receipt and the signed transaction expires unbroadcast.
   */
  async function chargeAfterFirstByte(parameters: {
    request: Request
    offers: { chargeAmount: bigint; description: string }
    validBefore?: number
    upstreamBody: Record<string, unknown>
    model: ModelPrice
    quote: { amount: bigint; promptTokens: number; maxTokens: number }
    requestId: string
    sanitized: ReturnType<typeof sanitizeChatRequest>
  }): Promise<Response> {
    const { request, offers, upstreamBody, model, quote, requestId, sanitized } = parameters
    const start = now()
    const deadline = parameters.validBefore !== undefined ? parameters.validBefore * 1000 - SETTLE_MARGIN_MS : start + MAX_FIRST_BYTE_WAIT_MS
    const abort = new AbortController()
    const signal = AbortSignal.any([request.signal, abort.signal])
    const notCharged = (status: number, type: string, message: string, upstreamStatus: number) => {
      log({ requestId, model: model.id, provider: model.provider, intent: 'charge', charged: '0', upstreamStatus })
      return errorResponse(status, type, message, { charged: false, ...(upstreamStatus ? { upstream_status: upstreamStatus } : {}) })
    }
    type First =
      | { ok: true; upstream: Response; reader: ReadableStreamDefaultReader<Uint8Array>; chunk: Uint8Array }
      | { ok: false; status: number; upstreamStatus: number }
    let timer: NodeJS.Timeout | undefined
    const first = await Promise.race<First | 'timeout'>([
      (async (): Promise<First> => {
        let upstream: Response
        try {
          upstream = await deps.upstream.chatCompletions(upstreamBody, signal)
        } catch {
          return { ok: false, status: 502, upstreamStatus: 0 }
        }
        if (!upstream.ok || !upstream.body) {
          await upstream.body?.cancel().catch(() => {})
          return { ok: false, status: upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502, upstreamStatus: upstream.status }
        }
        const reader = upstream.body.getReader()
        try {
          for (;;) {
            const { value, done } = await reader.read()
            if (done) return { ok: false, status: 502, upstreamStatus: upstream.status }
            if (value && value.byteLength > 0) return { ok: true, upstream, reader, chunk: value }
          }
        } catch {
          return { ok: false, status: 502, upstreamStatus: upstream.status }
        }
      })(),
      new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => resolve('timeout'), Math.max(0, deadline - start))
        timer.unref?.()
      }),
    ])
    if (timer) clearTimeout(timer)
    if (first === 'timeout') {
      abort.abort()
      return notCharged(504, 'upstream_timeout', 'the upstream did not answer before the payment expired; no charge was taken', 0)
    }
    if (!first.ok) return notCharged(first.status, 'upstream_error', 'the upstream failed before its first byte; no charge was taken', first.upstreamStatus)

    // The upstream is answering: take the charge now.
    const pay = await deps.payments.handle(request, offers).catch(() => undefined)
    if (!pay || pay.status === 402 || pay.intent !== 'charge') {
      abort.abort()
      await first.reader.cancel().catch(() => {})
      log({ requestId, model: model.id, provider: model.provider, intent: 'charge', charged: '0', upstreamStatus: first.upstream.status, settled: false })
      if (pay?.status === 402) return pay.challenge
      return errorResponse(502, 'charge_failed', 'the charge could not be settled; no charge was taken', { charged: false })
    }
    log({ requestId, model: model.id, provider: model.provider, intent: 'charge', charged: quote.amount.toString(), upstreamStatus: first.upstream.status })
    const { reader, chunk, upstream } = first
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk)
      },
      async pull(controller) {
        try {
          const { value, done } = await reader.read()
          if (done) controller.close()
          else controller.enqueue(value)
        } catch (error) {
          controller.error(error)
        }
      },
      async cancel(reason) {
        await reader.cancel(reason).catch(() => {})
      },
    })
    const headers = new Headers({ 'content-type': upstream.headers.get('content-type') ?? 'application/json' })
    const tapped = tapUsage(new Response(body, { status: upstream.status, headers }), (usage) => {
      onUsage({ model: model.id, promptTokens: usage?.prompt_tokens ?? quote.promptTokens, completionTokens: usage?.completion_tokens ?? 0 })
    })
    return pay.withReceipt(sanitized.stream && !sanitized.wantsUsage ? stripUsageChunks(tapped) : tapped)
  }

  app.get('/healthz', (c) => c.json({ ok: true }))
  app.get('/v1/models', (c) => c.json(modelsDocument(deps.prices, deps.gate)))
  app.get('/v1/attest-status', (c) =>
    c.json({
      providers: Object.fromEntries(deps.gate.all().map((s) => [s.provider, s])),
      sessions: deps.payments.sessionsEnabled,
    }),
  )

  const management = async (request: Request): Promise<Response> => {
    if (!deps.payments.sessionsEnabled) return errorResponse(400, 'invalid_request', 'request body required')
    const pay = await deps.payments.handle(request, {})
    if (pay.status === 402) return pay.challenge
    return pay.withReceipt(async function* () {})
  }

  // Hono routes HEAD through GET handlers; HEAD is the mppx session bootstrap probe.
  app.get('/v1/chat/completions', (c) =>
    c.req.raw.method === 'HEAD' ? management(c.req.raw) : errorResponse(405, 'method_not_allowed', 'use POST'),
  )

  const maxBodyBytes = deps.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  app.post(
    '/v1/chat/completions',
    bodyLimit({
      maxSize: maxBodyBytes,
      onError: () => errorResponse(413, 'request_too_large', `request body exceeds ${maxBodyBytes} bytes`),
    }),
    async (c, next) => {
      if (!deps.unpaidLimiter || hasPaymentCredential(c.req.raw)) return next()
      if (deps.unpaidLimiter.take(deps.clientKey?.(c) ?? 'unknown')) return next()
      return new Response(JSON.stringify({ error: { type: 'rate_limited', message: 'too many unpaid requests; retry later' } }), {
        status: 429,
        headers: { 'content-type': 'application/json', 'retry-after': '10' },
      })
    },
  )

  app.post('/v1/chat/completions', async (c) => {
    const request = c.req.raw
    const text = await request.clone().text()
    if (!text.trim()) return management(request)
    let body: ChatBody
    try {
      body = JSON.parse(text) as ChatBody
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object')
    } catch {
      return errorResponse(400, 'invalid_request', 'body must be a JSON object')
    }
    let sanitized: ReturnType<typeof sanitizeChatRequest>
    try {
      sanitized = sanitizeChatRequest(body)
    } catch (error) {
      if (error instanceof ChatRequestError) return errorResponse(400, error.type, error.message)
      throw error
    }
    const model =
      typeof body.model === 'string' ? findModel(deps.prices, body.model, (m) => deps.gate.allows(m.provider)) : undefined
    if (!model) return errorResponse(404, 'model_not_found', `unknown model ${String(body.model)}`)
    const refuse = () => {
      const status = deps.gate.status(model.provider)
      const type = status.enabled ? 'attestation_failed' : 'provider_unavailable'
      return errorResponse(503, type, `provider ${model.provider} is not usable: ${status.detail}`, { provider: model.provider })
    }
    if (!deps.gate.allows(model.provider)) return refuse()
    // A paid retry settles now: re-read the provider's attestation status first, so the window
    // in which a charge is taken for a provider that just failed is as small as possible.
    if (hasPaymentCredential(request) && deps.gate.refresh) {
      await deps.gate.refresh(model.provider)
      if (!deps.gate.allows(model.provider)) return refuse()
    }

    const quote = perRequestPrice(deps.prices, model, body)
    const offers = { chargeAmount: quote.amount, description: `${model.id}, up to ${quote.maxTokens} output tokens` }
    const requestId = randomUUID()
    const upstreamBody = buildUpstreamBody(sanitized, model, quote.maxTokens, body)

    const preflight = await deps.payments.preflightCharge(request, offers)
    if (preflight.kind === 'valid') {
      return chargeAfterFirstByte({ request, offers, validBefore: preflight.validBefore, upstreamBody, model, quote, requestId, sanitized })
    }
    // A charge credential that failed the preflight is never handed to mppx (which could still
    // settle it): the request is answered with a fresh challenge instead.
    const pay = await deps.payments.handle(preflight.kind === 'invalid' ? withoutCredential(request, text) : request, offers)
    if (pay.status === 402) return pay.challenge
    if (pay.intent === 'charge') {
      // Not reached: only a session credential or none gets here.
      return pay.withReceipt(errorResponse(500, 'charge_not_deferred', 'per-request charge settled outside the deferred path'))
    }

    const channelId = pay.channelId
    const { batchTokens, upstream, payments, prices } = deps
    return pay.withReceipt(async function* (stream: { charge(amount?: bigint): Promise<void>; signal: AbortSignal }) {
      const meter = new SessionMeter(model, prices.markupBps, { charge: (amount) => stream.charge(amount) }, {
        batchTokens,
        requestId,
        credit: channelId ? (amount, key) => payments.credit(channelId, amount, key) : undefined,
      })
      await meter.reservePrompt(quote.promptTokens)
      let upstreamStatus = 0
      let delivered = false
      let voided = false
      // Nothing was served (payments-6): owe nothing, give the whole prepayment back now, and tell the payer
      // whether any of it is still kept (`charged`), so it can offer a free retry when none is.
      const nothingServed = async (type: string, extra: Record<string, unknown> = {}) => {
        voided = true
        meter.voidAll()
        await meter.settleUnused().catch(() => {})
        return JSON.stringify({ error: { type, ...extra, charged: meter.result().chargedBaseUnits > 0n } })
      }
      try {
        let response: Response
        try {
          response = await upstream.chatCompletions(
            { ...upstreamBody, stream: true, stream_options: { include_usage: true } },
            stream.signal,
          )
        } catch {
          // Refused, reset or timed out before any answer (the relay's LiteLLM is down or restarting).
          yield await nothingServed('upstream_unreachable')
          return
        }
        upstreamStatus = response.status
        if (!response.ok) {
          await response.body?.cancel().catch(() => {})
          yield await nothingServed('upstream_error', { status: response.status })
          return
        }
        try {
          for await (const data of readUpstream(response)) {
            if (data === '[DONE]') break
            let chunk: ChatChunk
            try {
              chunk = JSON.parse(data) as ChatChunk
            } catch {
              continue
            }
            if (chunk.usage) await meter.reconcile(chunk.usage)
            await meter.beforeDeliver(chunk)
            yield data
            delivered = true
          }
        } catch (error) {
          // A failed charge keeps the prompt charge as before; only a broken upstream stream voids it.
          if (!(error instanceof UpstreamStreamError)) throw error
          if (delivered) throw error.cause
          // The upstream's stream broke before its first chunk reached the payer.
          yield await nothingServed('upstream_unreachable')
          return
        }
        yield '[DONE]'
      } finally {
        await meter.settleUnused().catch(() => {})
        const r = meter.result()
        onUsage({ model: model.id, promptTokens: upstreamStatus === 200 && !voided ? r.promptTokens : 0, completionTokens: r.completionTokens })
        log({
          requestId,
          model: model.id,
          provider: model.provider,
          intent: 'session',
          upstreamStatus,
          promptTokens: r.promptTokens,
          completionTokens: r.completionTokens,
          charged: r.chargedBaseUnits.toString(),
          credited: r.creditedBaseUnits.toString(),
          chargedDisplay: formatUnits(r.chargedBaseUnits, prices.decimals),
        })
      }
    })
  })

  return app
}
