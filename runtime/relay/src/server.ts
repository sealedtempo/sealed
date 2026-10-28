import { randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import { SessionMeter } from './metering.js'
import type { Payments } from './payments.js'
import {
  type ModelPrice,
  type PriceTable,
  costInBaseUnits,
  findModel,
  formatUnits,
  relayPricePer1M,
} from './prices.js'
import type { ProviderGate } from './providers/gate.js'
import { estimatePromptTokens } from './tokens.js'
import { type ChatChunk, type Upstream, sseData } from './upstream.js'

export type RelayDeps = {
  prices: PriceTable
  gate: Pick<ProviderGate, 'allows' | 'status' | 'all'>
  upstream: Upstream
  payments: Payments
  batchTokens: number
  /** Content-free request log: model, provider, intent, token counts and amounts only. */
  log?: (event: Record<string, unknown>) => void
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
  const promptTokens = estimatePromptTokens(body as { messages?: unknown })
  const maxTokens = boundedMaxTokens(body, model)
  return { amount: costInBaseUnits(model, prices.markupBps, BigInt(promptTokens), BigInt(maxTokens)), promptTokens, maxTokens }
}

export function modelsDocument(prices: PriceTable, gate: RelayDeps['gate']) {
  return {
    object: 'list',
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
    const model = typeof body.model === 'string' ? findModel(deps.prices, body.model) : undefined
    if (!model) return errorResponse(404, 'model_not_found', `unknown model ${String(body.model)}`)
    if (!deps.gate.allows(model.provider)) {
      const status = deps.gate.status(model.provider)
      const type = status.enabled ? 'attestation_failed' : 'provider_unavailable'
      return errorResponse(503, type, `provider ${model.provider} is not usable: ${status.detail}`, { provider: model.provider })
    }

    const quote = perRequestPrice(deps.prices, model, body)
    const pay = await deps.payments.handle(request, {
      chargeAmount: quote.amount,
      description: `${model.id}, up to ${quote.maxTokens} output tokens`,
    })
    if (pay.status === 402) return pay.challenge

    const requestId = randomUUID()
    const upstreamBody: Record<string, unknown> = { ...body, model: model.id, max_tokens: quote.maxTokens }
    if ('max_completion_tokens' in body) upstreamBody.max_completion_tokens = quote.maxTokens

    if (pay.intent === 'charge') {
      const upstream = await deps.upstream.chatCompletions(upstreamBody, request.signal).catch(() => undefined)
      log({ requestId, model: model.id, provider: model.provider, intent: 'charge', charged: quote.amount.toString(), upstreamStatus: upstream?.status ?? 0 })
      if (!upstream) return pay.withReceipt(errorResponse(502, 'upstream_unreachable', 'relay upstream unavailable'))
      const headers = new Headers({ 'content-type': upstream.headers.get('content-type') ?? 'application/json' })
      return pay.withReceipt(new Response(upstream.body, { status: upstream.status, headers }))
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
      try {
        const response = await upstream.chatCompletions(
          { ...upstreamBody, stream: true, stream_options: { include_usage: true } },
          stream.signal,
        )
        upstreamStatus = response.status
        if (!response.ok) {
          meter.voidAll()
          await response.body?.cancel().catch(() => {})
          yield JSON.stringify({ error: { type: 'upstream_error', status: response.status } })
          return
        }
        for await (const data of sseData(response)) {
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
        }
        yield '[DONE]'
      } finally {
        await meter.settleUnused().catch(() => {})
        const r = meter.result()
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
