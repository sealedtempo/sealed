/**
 * Token buckets per client key, for requests that have not paid yet (402 challenges, refusals).
 * Keys are bounded: the stalest buckets are dropped first.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>()

  constructor(
    private readonly options: { perMinute: number; burst?: number; maxKeys?: number; now?: () => number },
  ) {
    if (!(options.perMinute > 0)) throw new Error('perMinute must be positive')
  }

  /** Takes one token for key; false when the key is over its rate. */
  take(key: string): boolean {
    const now = (this.options.now ?? Date.now)()
    const burst = this.options.burst ?? this.options.perMinute
    const bucket = this.buckets.get(key) ?? { tokens: burst, at: now }
    bucket.tokens = Math.min(burst, bucket.tokens + ((now - bucket.at) / 60_000) * this.options.perMinute)
    bucket.at = now
    this.buckets.delete(key)
    this.buckets.set(key, bucket)
    this.prune()
    if (bucket.tokens < 1) return false
    bucket.tokens -= 1
    return true
  }

  private prune(): void {
    const max = this.options.maxKeys ?? 10_000
    while (this.buckets.size > max) {
      const oldest = this.buckets.keys().next().value
      if (oldest === undefined) return
      this.buckets.delete(oldest)
    }
  }
}

/**
 * The client a request comes from: the first X-Forwarded-For hop when the direct peer is a
 * trusted reverse proxy (Caddy replaces the header with the real client address), otherwise
 * the peer address.
 */
export function clientKey(remoteAddress: string | undefined, forwardedFor: string | null, trustedProxies: readonly string[]): string {
  const peer = (remoteAddress ?? '').replace(/^::ffff:/, '')
  if (forwardedFor && trustedProxies.includes(peer)) {
    const first = forwardedFor.split(',')[0]?.trim()
    if (first) return first
  }
  return peer || 'unknown'
}
