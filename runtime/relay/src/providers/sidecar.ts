import { Hono } from 'hono'
import type { ProviderId } from '../prices.js'
import { type ProviderStatus, type ProviderVerifier, type VerifiedChannel, nowSeconds } from './types.js'

/**
 * One verification sidecar per attested provider. It keeps a verified channel to the
 * provider, re-verifies with a fresh nonce before the evidence expires, and forwards
 * OpenAI-compatible calls from the relay's LiteLLM only over that channel. When
 * verification fails it refuses to forward (503) until a later verification passes.
 */
export class ProviderSidecar {
  private channel: VerifiedChannel | undefined
  private status: ProviderStatus
  private timer: NodeJS.Timeout | undefined
  private inflight: Promise<void> | undefined
  private stopped = false

  constructor(
    private readonly verifier: ProviderVerifier | undefined,
    private readonly options: { provider: ProviderId; refreshSeconds?: number; retrySeconds?: number; log?: (line: string) => void },
  ) {
    this.status = verifier
      ? { provider: options.provider, enabled: true, verified: false, detail: 'verification pending' }
      : { provider: options.provider, enabled: false, verified: false, detail: 'provider API key not configured' }
  }

  getStatus(): ProviderStatus {
    if (this.status.verified && this.status.expiresAt !== undefined && this.status.expiresAt <= nowSeconds())
      return { ...this.status, verified: false, detail: 'evidence expired; re-verifying' }
    return this.status
  }

  isUsable(): boolean {
    return this.getStatus().verified && this.channel !== undefined
  }

  start(): void {
    if (!this.verifier) return
    void this.refresh()
  }

  async stop(): Promise<void> {
    this.stopped = true
    if (this.timer) clearTimeout(this.timer)
    await this.channel?.close?.().catch(() => {})
  }

  /** Runs one verification now (deduplicated) and schedules the next one. */
  refresh(): Promise<void> {
    if (!this.verifier) return Promise.resolve()
    this.inflight ??= this.runVerification().finally(() => {
      this.inflight = undefined
    })
    return this.inflight
  }

  private async runVerification(): Promise<void> {
    const verifier = this.verifier!
    let nextInSeconds: number
    try {
      const channel = await verifier.verify()
      const previous = this.channel
      this.channel = channel
      if (previous && previous !== channel) void previous.close?.().catch(() => {})
      this.status = {
        provider: this.options.provider,
        enabled: true,
        verified: true,
        verifiedAt: nowSeconds(),
        expiresAt: channel.expiresAt,
        detail: 'attestation verified',
        evidence: channel.evidence,
      }
      const refresh = this.options.refreshSeconds ?? 600
      nextInSeconds = Math.max(5, Math.min(refresh, channel.expiresAt - nowSeconds() - 60))
      this.options.log?.(`${this.options.provider}: attestation verified`)
    } catch (error) {
      this.markFailed((error as Error).message)
      nextInSeconds = this.options.retrySeconds ?? 30
    }
    if (!this.stopped) {
      if (this.timer) clearTimeout(this.timer)
      this.timer = setTimeout(() => void this.refresh(), nextInSeconds * 1000)
      this.timer.unref?.()
    }
  }

  private markFailed(detail: string): void {
    const previous = this.channel
    this.channel = undefined
    void previous?.close?.().catch(() => {})
    this.status = { provider: this.options.provider, enabled: true, verified: false, detail }
    this.options.log?.(`${this.options.provider}: attestation failed: ${detail}`)
  }

  /** Forwards one request to the verified provider endpoint. */
  async forward(path: string, request: Request): Promise<Response> {
    if (!this.isUsable() || !this.channel) {
      const status = this.getStatus()
      return Response.json(
        { error: { type: 'attestation_failed', provider: this.options.provider, message: status.detail } },
        { status: 503 },
      )
    }
    const channel = this.channel
    const headers = new Headers()
    for (const name of ['authorization', 'content-type', 'accept']) {
      const value = request.headers.get(name)
      if (value) headers.set(name, value)
    }
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD'
    let upstream: Response
    try {
      upstream = await channel.fetch(`${channel.baseURL}${path}`, {
        method: request.method,
        headers,
        body: hasBody ? await request.arrayBuffer() : undefined,
        signal: request.signal,
      })
    } catch (error) {
      const message = (error as Error).message ?? String(error)
      const cause = (error as { cause?: { message?: string } }).cause?.message ?? ''
      if (/pin check|not attested|peer key/i.test(`${message} ${cause}`)) {
        this.markFailed(`TLS key no longer matches attestation: ${cause || message}`)
        void this.refresh()
        return Response.json(
          { error: { type: 'attestation_failed', provider: this.options.provider, message: 'TLS key mismatch' } },
          { status: 503 },
        )
      }
      return Response.json({ error: { type: 'upstream_unreachable', provider: this.options.provider } }, { status: 502 })
    }
    const out = new Headers()
    for (const name of ['content-type', 'cache-control', 'x-request-id']) {
      const value = upstream.headers.get(name)
      if (value) out.set(name, value)
    }
    return new Response(upstream.body, { status: upstream.status, headers: out })
  }

  app(): Hono {
    const app = new Hono()
    app.get('/healthz', (c) => c.json({ ok: true }))
    app.get('/v1/status', (c) => c.json(this.getStatus()))
    app.all('/v1/*', async (c) => {
      const url = new URL(c.req.url)
      return this.forward(url.pathname.slice('/v1'.length) + url.search, c.req.raw)
    })
    return app
  }
}
