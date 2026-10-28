import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import type { ProviderId } from '../prices.js'
import type { FetchLike, ProviderStatus } from './types.js'
import { nowSeconds } from './types.js'

/** Where the relay front learns whether a provider is attested right now. */
export type StatusSource =
  | { kind: 'sidecar'; statusUrl: string }
  /**
   * Edgeless's Privatemode proxy attests the deployment against its manifest and only encrypts
   * with a key it obtained after attestation; it answers 500 while it holds none. The proof that
   * it is serving verified traffic is an authenticated one-token completion through it.
   */
  | {
      kind: 'privatemode'
      baseUrl: string
      apiKey: () => string | undefined
      model: string
      /** The proxy's workspace (read-only mount), for the manifest it logged. */
      workspaceDir?: string
      probeSeconds?: number
    }

export type GateEntry = { provider: ProviderId; enabled: boolean; source: StatusSource }

/** Latest manifest the Privatemode proxy logged (workspace/manifests/log.txt names it). */
export function privatemodeManifestEvidence(workspaceDir: string): Record<string, string> {
  try {
    const dir = join(workspaceDir, 'manifests')
    const lines = readFileSync(join(dir, 'log.txt'), 'utf8').trim().split('\n').filter(Boolean)
    const last = lines.at(-1)
    if (!last) return { manifest: 'not logged yet' }
    const [loggedAt, path] = last.split(' ')
    const bytes = readFileSync(join(dir, basename(path ?? '')))
    return { manifestSha256: createHash('sha256').update(bytes).digest('hex'), manifestLoggedAt: loggedAt ?? '', manifestVersion: String(lines.length) }
  } catch (error) {
    return { manifest: `unreadable: ${(error as NodeJS.ErrnoException).code ?? (error as Error).message}` }
  }
}

/**
 * Relay-front view of provider attestation. Statuses are polled, and a request is only
 * forwarded when its provider's last status is verified and not expired. Anything else
 * (disabled, unreachable sidecar, failed or stale evidence) refuses the request.
 */
export class ProviderGate {
  private readonly statuses = new Map<ProviderId, ProviderStatus>()
  private readonly polledAt = new Map<ProviderId, number>()
  private readonly inflight = new Map<ProviderId, Promise<void>>()
  private timer: NodeJS.Timeout | undefined

  constructor(
    private readonly entries: GateEntry[],
    private readonly options: { fetch?: FetchLike; pollSeconds?: number; maxStatusAgeSeconds?: number; now?: () => number } = {},
  ) {
    for (const entry of entries)
      this.statuses.set(entry.provider, {
        provider: entry.provider,
        enabled: entry.enabled,
        verified: false,
        detail: entry.enabled ? 'status pending' : 'provider API key not configured',
      })
  }

  start(): void {
    void this.pollAll()
    this.timer = setInterval(() => void this.pollAll(), (this.options.pollSeconds ?? 15) * 1000)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
  }

  async pollAll(): Promise<void> {
    await Promise.all(this.entries.filter((e) => e.enabled).map((e) => this.pollIfDue(e)))
  }

  /**
   * Re-reads one provider's status now, right before a payment settles. Sidecar statuses are
   * local and cheap; a Privatemode probe is a billed completion, so it keeps its own schedule.
   */
  async refresh(provider: ProviderId): Promise<void> {
    const entry = this.entries.find((e) => e.provider === provider)
    if (!entry?.enabled) return
    if (entry.source.kind === 'sidecar') await this.poll(entry)
    else await this.pollIfDue(entry)
  }

  status(provider: ProviderId): ProviderStatus {
    const status = this.statuses.get(provider)
    if (!status) return { provider, enabled: false, verified: false, detail: 'unknown provider' }
    if (status.verified && status.expiresAt !== undefined && status.expiresAt <= this.now())
      return { ...status, verified: false, detail: 'evidence expired' }
    return status
  }

  all(): ProviderStatus[] {
    return this.entries.map((e) => this.status(e.provider))
  }

  /** True only for an enabled provider with fresh, verified evidence. */
  allows(provider: ProviderId): boolean {
    const s = this.status(provider)
    return s.enabled && s.verified
  }

  private now(): number {
    return (this.options.now ?? nowSeconds)()
  }

  private pollIfDue(entry: GateEntry): Promise<void> {
    if (entry.source.kind === 'privatemode') {
      const last = this.polledAt.get(entry.provider)
      if (last !== undefined && this.now() - last < (entry.source.probeSeconds ?? 120)) return Promise.resolve()
    }
    return this.poll(entry)
  }

  private poll(entry: GateEntry): Promise<void> {
    const running = this.inflight.get(entry.provider)
    if (running) return running
    const run = this.pollOnce(entry).finally(() => {
      this.inflight.delete(entry.provider)
      this.polledAt.set(entry.provider, this.now())
    })
    this.inflight.set(entry.provider, run)
    return run
  }

  private async pollOnce(entry: GateEntry): Promise<void> {
    const fetchImpl = this.options.fetch ?? fetch
    const maxAge = this.options.maxStatusAgeSeconds ?? 60
    try {
      if (entry.source.kind === 'sidecar') {
        const res = await fetchImpl(entry.source.statusUrl, { signal: AbortSignal.timeout(5_000) })
        if (!res.ok) throw new Error(`sidecar status HTTP ${res.status}`)
        const body = (await res.json()) as Partial<ProviderStatus>
        this.statuses.set(entry.provider, {
          provider: entry.provider,
          enabled: entry.enabled && body.enabled === true,
          verified: body.verified === true,
          verifiedAt: body.verifiedAt,
          expiresAt: body.verified === true ? Math.min(body.expiresAt ?? Infinity, this.now() + maxAge) : undefined,
          detail: typeof body.detail === 'string' ? body.detail : 'no detail',
          evidence: body.evidence,
        })
        return
      }
      const source = entry.source
      const key = source.apiKey()
      if (!key) throw new Error('PRIVATEMODE_API_KEY not readable by the relay front')
      const res = await fetchImpl(`${source.baseUrl.replace(/\/+$/, '')}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
        body: JSON.stringify({ model: source.model, messages: [{ role: 'user', content: 'ok' }], max_tokens: 1, stream: false }),
        signal: AbortSignal.timeout(30_000),
      })
      await res.body?.cancel().catch(() => {})
      const evidence = {
        method: 'authenticated completion through privatemode-proxy (encrypts only with a key released after attestation)',
        probeStatus: String(res.status),
        ...(source.workspaceDir ? privatemodeManifestEvidence(source.workspaceDir) : {}),
      }
      const at = this.now()
      this.statuses.set(entry.provider, {
        provider: entry.provider,
        enabled: entry.enabled,
        verified: res.ok,
        verifiedAt: res.ok ? at : undefined,
        expiresAt: res.ok ? at + (source.probeSeconds ?? 120) + maxAge : undefined,
        detail: res.ok ? 'attested by privatemode-proxy; probe completion succeeded' : `privatemode-proxy refused the probe (HTTP ${res.status})`,
        evidence,
      })
    } catch (error) {
      this.statuses.set(entry.provider, {
        provider: entry.provider,
        enabled: entry.enabled,
        verified: false,
        detail: `status unavailable: ${(error as Error).message}`,
      })
    }
  }
}
