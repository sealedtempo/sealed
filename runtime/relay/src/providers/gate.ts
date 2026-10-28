import type { ProviderId } from '../prices.js'
import type { FetchLike, ProviderStatus } from './types.js'
import { nowSeconds } from './types.js'

/** Where the relay front learns whether a provider is attested right now. */
export type StatusSource =
  | { kind: 'sidecar'; statusUrl: string }
  /** A binary proxy that enforces attestation itself (Privatemode); we probe that it serves verified traffic. */
  | { kind: 'probe'; probeUrl: string }

export type GateEntry = { provider: ProviderId; enabled: boolean; source: StatusSource }

/**
 * Relay-front view of provider attestation. Statuses are polled, and a request is only
 * forwarded when its provider's last status is verified and not expired. Anything else
 * (disabled, unreachable sidecar, failed or stale evidence) refuses the request.
 */
export class ProviderGate {
  private readonly statuses = new Map<ProviderId, ProviderStatus>()
  private timer: NodeJS.Timeout | undefined

  constructor(
    private readonly entries: GateEntry[],
    private readonly options: { fetch?: FetchLike; pollSeconds?: number; maxStatusAgeSeconds?: number } = {},
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
    await Promise.all(this.entries.filter((e) => e.enabled).map((e) => this.poll(e)))
  }

  status(provider: ProviderId): ProviderStatus {
    const status = this.statuses.get(provider)
    if (!status) return { provider, enabled: false, verified: false, detail: 'unknown provider' }
    if (status.verified && status.expiresAt !== undefined && status.expiresAt <= nowSeconds())
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

  private async poll(entry: GateEntry): Promise<void> {
    const fetchImpl = this.options.fetch ?? fetch
    const maxAge = this.options.maxStatusAgeSeconds ?? 60
    const signal = AbortSignal.timeout(5_000)
    try {
      if (entry.source.kind === 'sidecar') {
        const res = await fetchImpl(entry.source.statusUrl, { signal })
        if (!res.ok) throw new Error(`sidecar status HTTP ${res.status}`)
        const body = (await res.json()) as Partial<ProviderStatus>
        this.statuses.set(entry.provider, {
          provider: entry.provider,
          enabled: entry.enabled && body.enabled === true,
          verified: body.verified === true,
          verifiedAt: body.verifiedAt,
          expiresAt: body.verified === true ? Math.min(body.expiresAt ?? Infinity, nowSeconds() + maxAge) : undefined,
          detail: typeof body.detail === 'string' ? body.detail : 'no detail',
          evidence: body.evidence,
        })
      } else {
        const res = await fetchImpl(entry.source.probeUrl, { signal })
        await res.body?.cancel().catch(() => {})
        this.statuses.set(entry.provider, {
          provider: entry.provider,
          enabled: entry.enabled,
          verified: res.ok,
          verifiedAt: res.ok ? nowSeconds() : undefined,
          expiresAt: res.ok ? nowSeconds() + maxAge : undefined,
          detail: res.ok ? 'attestation enforced by provider proxy' : `provider proxy refused (HTTP ${res.status})`,
        })
      }
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
