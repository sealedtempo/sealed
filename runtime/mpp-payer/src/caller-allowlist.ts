import { lookup } from 'node:dns/promises'

/**
 * Only the stack's llm-gateway may spend through the payer. Allowed callers are compose
 * service names (network aliases); their apps-network addresses are resolved through Docker's
 * DNS and refreshed periodically. An empty list allows everyone (local development only).
 */
export class CallerAllowlist {
  private addresses = new Set<string>()
  private resolvedOnce = false
  private timer: NodeJS.Timeout | undefined

  constructor(
    private readonly names: string[],
    private readonly resolve: (name: string) => Promise<string[]> = async (name) =>
      (await lookup(name, { all: true })).map((a) => a.address),
  ) {}

  static normalize(address: string | undefined): string {
    if (!address) return ''
    return address.startsWith('::ffff:') ? address.slice(7) : address
  }

  async refresh(): Promise<void> {
    if (this.names.length === 0) return
    const next = new Set<string>()
    let anyResolved = false
    for (const name of this.names) {
      try {
        for (const a of await this.resolve(name)) next.add(CallerAllowlist.normalize(a))
        anyResolved = true
      } catch {
        // keep previous addresses for names that fail to resolve this round
        for (const a of this.addresses) next.add(a)
      }
    }
    if (anyResolved || !this.resolvedOnce) this.addresses = next
    this.resolvedOnce ||= anyResolved
  }

  start(intervalSeconds = 60): void {
    void this.refresh()
    this.timer = setInterval(() => void this.refresh(), intervalSeconds * 1000)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
  }

  allows(remoteAddress: string | undefined): boolean {
    if (this.names.length === 0) return true
    const address = CallerAllowlist.normalize(remoteAddress)
    if (address === '127.0.0.1' || address === '::1') return true
    return this.addresses.has(address)
  }
}
