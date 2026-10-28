import { type Context, Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import type { GateState } from './attestation-gate.js'
import { CompletionAccumulator, sseFrame } from './openai.js'
import { type RelayResult, RelaySessionFailedError } from './relay-client.js'
import { RelayChannelError } from './relay-transport.js'
import { sseData } from './sse.js'
import { BudgetUnavailableError } from './shared-budget.js'
import { PaymentPolicyError, SpendLimitError } from './spend-guard.js'

/** The relay refuses bodies above 4 MiB (runtime/relay DEFAULT_MAX_BODY_BYTES); the payer stops reading there too. */
export const MAX_BODY_BYTES = 4 * 1024 * 1024

export type PayerDeps = {
  gate: { ensureFresh(): Promise<GateState>; isOpen(): boolean }
  relay: { chat(body: Record<string, unknown>, signal?: AbortSignal): Promise<RelayResult>; sessionsAvailable(): boolean }
  models: () => Promise<Response>
  callers: { allows(address: string | undefined): boolean }
  remoteAddress: (c: Context) => string | undefined
  onPayment?: () => void
  /** Content-free request log (never prompts or outputs). */
  log?: (event: Record<string, unknown>) => void
}

function error(status: number, type: string, message: string): Response {
  return Response.json({ error: { type, message } }, { status })
}

/**
 * 424: the relay took a per-request charge and then failed. LiteLLM and the OpenAI SDKs retry
 * 429 and 5xx; a retried charge would be paid again, so this answer is a 4xx they do not retry.
 */
function failedAfterPayment(detail: string, upstreamStatus?: number): Response {
  return Response.json(
    {
      error: {
        type: 'relay_failed_after_payment',
        message: `the relay was paid for this request and then failed (${detail}); it is not retried automatically`,
        ...(upstreamStatus !== undefined ? { relay_status: upstreamStatus } : {}),
      },
    },
    { status: 424 },
  )
}

function passthroughHeaders(from: Headers): Headers {
  const out = new Headers()
  for (const name of ['content-type', 'cache-control']) {
    const value = from.get(name)
    if (value) out.set(name, value)
  }
  return out
}

function streamSession(events: AsyncIterable<string>, onDone: () => void): Response {
  const encoder = new TextEncoder()
  const iterator = events[Symbol.asyncIterator]()
  let finished = false
  const finish = () => {
    if (finished) return
    finished = true
    onDone()
  }
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await iterator.next()
        if (done) {
          controller.enqueue(encoder.encode(sseFrame('[DONE]')))
          controller.close()
          finish()
          return
        }
        controller.enqueue(encoder.encode(sseFrame(value)))
        if (value === '[DONE]') {
          controller.close()
          finish()
          await iterator.return?.()
        }
      } catch (err) {
        const policy =
          err instanceof SpendLimitError ? 'spend_limit_exceeded' : err instanceof BudgetUnavailableError ? 'spend_budget_unavailable' : 'relay_stream_failed'
        controller.enqueue(encoder.encode(sseFrame(JSON.stringify({ error: { type: policy, message: (err as Error).message } }))))
        controller.enqueue(encoder.encode(sseFrame('[DONE]')))
        controller.close()
        finish()
      }
    },
    async cancel() {
      finish()
      await iterator.return?.()
    },
  })
  return new Response(body, { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-store' } })
}

/**
 * The payer's OpenAI-compatible surface for LiteLLM's relay/* routes. Every request passes the
 * caller allowlist and the relay attestation gate before any payment; prompts go only to the
 * relay, and only content-free facts are logged.
 */
export function createPayerApp(deps: PayerDeps): Hono {
  const app = new Hono()
  const log = deps.log ?? (() => {})

  app.get('/healthz', (c) => c.json({ ok: true, relayAttested: deps.gate.isOpen(), sessions: deps.relay.sessionsAvailable() }))

  app.use('/v1/*', async (c, next) => {
    if (!deps.callers.allows(deps.remoteAddress(c))) return error(403, 'forbidden_caller', 'caller is not allowed to spend through the payer')
    return next()
  })

  const attestationFailed = (detail: string) =>
    error(503, 'relay_attestation_failed', `relay attestation failed, refusing to send requests: ${detail}`)

  app.get('/v1/models', async () => {
    const gate = await deps.gate.ensureFresh()
    if (!gate.ok) return attestationFailed(gate.detail)
    try {
      const res = await deps.models()
      return new Response(res.body, { status: res.status, headers: passthroughHeaders(res.headers) })
    } catch (err) {
      if (err instanceof RelayChannelError) return attestationFailed(err.message)
      return error(502, 'relay_unreachable', 'relay model list unavailable')
    }
  })

  app.post(
    '/v1/chat/completions',
    bodyLimit({ maxSize: MAX_BODY_BYTES, onError: () => error(413, 'request_too_large', `request body exceeds ${MAX_BODY_BYTES} bytes`) }),
  )

  app.post('/v1/chat/completions', async (c) => {
    const gate = await deps.gate.ensureFresh()
    if (!gate.ok) return attestationFailed(gate.detail)

    let body: Record<string, unknown>
    try {
      body = (await c.req.json()) as Record<string, unknown>
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object')
    } catch {
      return error(400, 'invalid_request', 'body must be a JSON object')
    }
    const wantsStream = body.stream === true
    const model = typeof body.model === 'string' ? body.model : ''

    let result: RelayResult
    try {
      result = await deps.relay.chat(body, c.req.raw.signal)
    } catch (err) {
      if (err instanceof SpendLimitError) return error(429, 'spend_limit_exceeded', err.message)
      if (err instanceof BudgetUnavailableError) return error(503, 'spend_budget_unavailable', err.message)
      if (err instanceof PaymentPolicyError) return error(502, 'payment_refused', err.message)
      if (err instanceof RelayChannelError) {
        log({ event: 'relay_channel_refused', model, detail: err.message.slice(0, 200) })
        return attestationFailed(err.message)
      }
      if (err instanceof RelaySessionFailedError) {
        log({ event: 'relay_session_failed', model, detail: (err.cause as Error)?.message?.slice(0, 200) })
        return error(502, 'relay_session_failed', 'the relay session failed after the request was sent')
      }
      log({ event: 'relay_request_failed', model, detail: (err as Error).message?.slice(0, 200) })
      return error(502, 'relay_unreachable', 'relay request failed')
    } finally {
      deps.onPayment?.()
    }

    if (result.kind === 'response') {
      const { response, paid } = result
      log({ event: 'relay_request', model, intent: result.intent, status: response.status, paid })
      if (paid && response.status >= 400) {
        await response.body?.cancel().catch(() => {})
        return failedAfterPayment(`relay status ${response.status}`, response.status)
      }
      // A charge is always sent as a stream (the relay settles it after the upstream's first
      // byte); a non-stream caller gets it folded back into one chat.completion.
      if (result.streamed && !wantsStream && response.ok) {
        const acc = new CompletionAccumulator()
        try {
          for await (const data of sseData(response)) {
            if (data === '[DONE]') break
            acc.add(data)
          }
        } catch (err) {
          return paid ? failedAfterPayment('stream interrupted') : error(502, 'relay_stream_failed', (err as Error).message)
        }
        if (acc.error !== undefined) return paid ? failedAfterPayment('upstream error in the stream') : Response.json({ error: acc.error }, { status: 502 })
        return Response.json(acc.result(model))
      }
      return new Response(response.body, { status: response.status, headers: passthroughHeaders(response.headers) })
    }

    log({ event: 'relay_request', model, intent: 'session', stream: wantsStream })
    if (wantsStream) return streamSession(result.events, () => deps.onPayment?.())

    const acc = new CompletionAccumulator()
    try {
      for await (const data of result.events) {
        if (data === '[DONE]') break
        acc.add(data)
      }
    } catch (err) {
      if (err instanceof SpendLimitError) return error(429, 'spend_limit_exceeded', err.message)
      if (err instanceof BudgetUnavailableError) return error(503, 'spend_budget_unavailable', err.message)
      return error(502, 'relay_stream_failed', (err as Error).message)
    } finally {
      deps.onPayment?.()
    }
    if (acc.error !== undefined) return Response.json({ error: acc.error }, { status: 502 })
    return Response.json(acc.result(model))
  })

  return app
}
