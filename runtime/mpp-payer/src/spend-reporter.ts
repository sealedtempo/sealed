import type { RecoveryCounters } from './channel-recovery.js'
import type { SpendCounters } from './spend-guard.js'

export type SpendReport = {
  source: 'sealed-mpp-payer'
  mode: string
  currency: string
  counters: SpendCounters
  relay: { attested: boolean; checkedAt?: number; stackHash?: string; sessionsAvailable: boolean }
  /** Orphaned-channel recovery counters; sealed-agent reports them as mpp_recovery* (runtime/agent/src/spend.ts). */
  recovery: RecoveryCounters
  sentAt: number
}

/** The parts of the running payer a spend report is read from (main.ts passes the real ones). */
export type SpendSources = {
  mode: string
  currency: string
  guard: { counters(): SpendCounters }
  gate: { isOpen(): boolean; state(): { checkedAt?: number; stackHash?: string } }
  relay: { sessionsAvailable(): boolean }
  /** ChannelRecovery: its counters go to the agent with every report (they were once kept in the payer only). */
  recovery: { snapshot(): RecoveryCounters }
}

/** What the payer reports to sealed-agent: its counters, the relay attestation state and the recovery counters. */
export function spendSnapshot(s: SpendSources): Omit<SpendReport, 'sentAt' | 'source'> {
  const gate = s.gate.state()
  return {
    mode: s.mode,
    currency: s.currency,
    counters: s.guard.counters(),
    relay: { attested: s.gate.isOpen(), checkedAt: gate.checkedAt, stackHash: gate.stackHash, sessionsAvailable: s.relay.sessionsAvailable() },
    recovery: s.recovery.snapshot(),
  }
}

/**
 * Pushes content-free spend counters to sealed-agent (POST /v1/spend): amounts, counts and the
 * relay attestation state only, never prompts or outputs. Sends periodically and shortly after
 * each payment, coalescing bursts.
 */
export class SpendReporter {
  private timer: NodeJS.Timeout | undefined
  private pending: NodeJS.Timeout | undefined
  private lastError: string | undefined

  constructor(
    private readonly deps: {
      agentUrl: string
      snapshot: () => Omit<SpendReport, 'sentAt' | 'source'>
      intervalSeconds: number
      fetch?: (input: string, init: RequestInit) => Promise<Response>
      log?: (event: Record<string, unknown>) => void
    },
  ) {}

  start(): void {
    this.timer = setInterval(() => void this.send(), this.deps.intervalSeconds * 1000)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
    if (this.pending) clearTimeout(this.pending)
  }

  /** Schedules a send within a second, coalescing calls. */
  poke(): void {
    if (this.pending) return
    this.pending = setTimeout(() => {
      this.pending = undefined
      void this.send()
    }, 1000)
    this.pending.unref?.()
  }

  async send(): Promise<boolean> {
    const report: SpendReport = { source: 'sealed-mpp-payer', ...this.deps.snapshot(), sentAt: Math.floor(Date.now() / 1000) }
    try {
      const res = await (this.deps.fetch ?? fetch)(`${this.deps.agentUrl}/v1/spend`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(report),
        signal: AbortSignal.timeout(5_000),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      this.lastError = undefined
      return true
    } catch (error) {
      const message = (error as Error).message
      if (message !== this.lastError) this.deps.log?.({ event: 'spend_report_failed', detail: message })
      this.lastError = message
      return false
    }
  }
}
