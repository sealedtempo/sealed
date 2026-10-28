import type { Store } from 'mppx'
import { tempo } from 'mppx/server'
import type { Account, Client } from 'viem'
import type { PgStore } from './pg-store.js'

const TERMINAL = new Set(['closed', 'unrecovered', 'finalized', 'missing'])

export type SupervisionSummary = {
  supervised: number
  settled: number
  closed: number
  failed: number
  unrecovered: number
  finalized: string[]
}

type SuperviseFn = (parameters: {
  account: Account
  channelIds: Iterable<`0x${string}`>
  client: Client
  store: Store.AtomicStore
  previousBlock?: bigint
  settlementSchedule?: { amount?: bigint; intervalMs?: number; units?: number }
}) => Promise<{
  block: bigint
  complete: boolean
  supervised: number
  settled: number
  closed: number
  failed: number
  unrecovered: number
  channels: { channelId: `0x${string}`; outcome: string }[]
}>

/**
 * Settlement and close supervisor for MPP sessions. Every interval it hands mppx's
 * `superviseCloses` the open channel ids from Postgres (the mppx store cannot list them):
 * mppx settles channels whose spend crossed the schedule, captures spend from channels whose
 * payer requested a close (before the 900 s grace period lets the payer withdraw), and marks
 * terminal channels so they drop out of later runs.
 */
export class SettlementSupervisor {
  private previousBlock: bigint | undefined
  private timer: NodeJS.Timeout | undefined
  private running = false

  constructor(
    private readonly deps: {
      db: Pick<PgStore, 'listChannels' | 'markFinalized'>
      store: Store.AtomicStore
      client: Client
      account: Account
      schedule?: { amount?: bigint; intervalMs?: number }
      intervalSeconds?: number
      supervise?: SuperviseFn
      log?: (event: Record<string, unknown>) => void
    },
  ) {}

  start(): void {
    this.timer = setInterval(() => void this.runOnce().catch(() => {}), (this.deps.intervalSeconds ?? 60) * 1000)
    this.timer.unref?.()
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer)
  }

  async runOnce(): Promise<SupervisionSummary | undefined> {
    if (this.running) return undefined
    this.running = true
    try {
      const channels = await this.deps.db.listChannels()
      if (channels.length === 0) return { supervised: 0, settled: 0, closed: 0, failed: 0, unrecovered: 0, finalized: [] }
      const supervise = this.deps.supervise ?? (tempo.session.superviseCloses as unknown as SuperviseFn)
      const result = await supervise({
        account: this.deps.account,
        channelIds: channels.map((c) => c.channelId),
        client: this.deps.client,
        store: this.deps.store,
        previousBlock: this.previousBlock,
        settlementSchedule: this.deps.schedule,
      })
      if (result.complete) this.previousBlock = result.block
      const finalized: string[] = []
      for (const channel of result.channels) {
        if (!TERMINAL.has(channel.outcome)) continue
        await this.deps.db.markFinalized(channel.channelId)
        finalized.push(channel.channelId)
      }
      const summary = {
        supervised: result.supervised,
        settled: result.settled,
        closed: result.closed,
        failed: result.failed,
        unrecovered: result.unrecovered,
        finalized,
      }
      this.deps.log?.({ event: 'supervision', ...summary, finalized: finalized.length })
      return summary
    } finally {
      this.running = false
    }
  }
}
