import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * Local spend guard, the payer's second cap. Every debit of the customer's money (a per-request
 * charge, a channel deposit, a channel top-up, and the network fee of a transaction the payer
 * pays itself) reserves budget here before its credential leaves the payer. The first cap is
 * sealed-agent's shared daily budget (D-048, shared-budget.ts), which also holds back what fee
 * settlement needs. This guard caps the payer at the daily limit (SPEND_LIMIT_PER_DAY) per UTC
 * day on its own, so a lost or misbehaving agent budget cannot let it spend more. Refunds from
 * cooperative channel closes give budget back. The day's debits are persisted, so a restart (or
 * a crash loop) does not reset the budget. The protocol's own access-key limit is the hard cap
 * in access-key mode.
 */
export class SpendLimitError extends Error {
  constructor(
    readonly requested: bigint,
    readonly remaining: bigint,
    /** local: this guard; shared: sealed-agent's shared budget (fee settlement has priority). */
    readonly scope: 'local' | 'shared' = 'local',
    /** The shared budget's reason when it is not plain lack of budget (for example too_many_reservations). */
    readonly reason?: string,
  ) {
    super(
      scope === 'shared'
        ? `shared daily budget refused (fee settlement has priority${reason ? `; ${reason}` : ''}): requested ${requested}, remaining ${remaining} base units`
        : `daily spend limit reached: requested ${requested}, remaining ${remaining} base units`,
    )
    this.name = 'SpendLimitError'
  }
}

export class PaymentPolicyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PaymentPolicyError'
  }
}

/** fee: the network fee cap of a transaction the payer's account pays itself (it counts against the access-key limit). */
export type DebitKind = 'charge' | 'deposit' | 'topUp' | 'fee'

export type SpendCounters = {
  day: string
  limit: string
  /** This guard's daily cap: the whole limit (the shared budget in sealed-agent is the first cap). */
  budget: string
  /** Every debit, network fee caps included. */
  debited: string
  remaining: string
  charges: number
  chargeAmount: string
  deposits: number
  depositAmount: string
  topUps: number
  topUpAmount: string
  refunded: string
  refused: number
  /** Highest voucher authorization per open channel, summed: what the relay may have consumed. */
  sessionAuthorized: string
}

function utcDay(now: number): string {
  return new Date(now).toISOString().slice(0, 10)
}

/** Persisted state of one UTC day; amounts are decimal strings of base units. */
export type SpendState = {
  day: string
  debited: string
  refunded: string
  refused: number
  byKind: Record<DebitKind, { n: number; amount: string }>
}

export interface SpendStore {
  load(): SpendState | undefined
  save(state: SpendState): void
}

/** A small JSON file, replaced atomically on every change. Read or write errors never block payments. */
export class FileSpendStore implements SpendStore {
  constructor(
    private readonly path: string,
    private readonly onError: (error: Error) => void = () => {},
  ) {}

  load(): SpendState | undefined {
    try {
      const state = JSON.parse(readFileSync(this.path, 'utf8')) as SpendState
      if (typeof state?.day !== 'string' || !/^\d+$/.test(state.debited) || !/^\d+$/.test(state.refunded)) return undefined
      return state
    } catch {
      return undefined
    }
  }

  save(state: SpendState): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      const tmp = `${this.path}.tmp`
      writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 })
      renameSync(tmp, this.path)
    } catch (error) {
      this.onError(error as Error)
    }
  }
}

export type SpendGuardOptions = { store?: SpendStore }

export class SpendGuard {
  private day: string
  private debited = 0n
  private refunded = 0n
  private refused = 0
  private readonly byKind = { charge: { n: 0, amount: 0n }, deposit: { n: 0, amount: 0n }, topUp: { n: 0, amount: 0n }, fee: { n: 0, amount: 0n } }
  private readonly vouchers = new Map<string, bigint>()
  private readonly store: SpendStore | undefined

  constructor(
    readonly limitPerDay: bigint,
    private readonly now: () => number = Date.now,
    options: SpendGuardOptions = {},
  ) {
    if (limitPerDay < 0n) throw new Error('negative spend limit')
    this.store = options.store
    this.day = utcDay(this.now())
    const saved = this.store?.load()
    if (saved && saved.day === this.day) {
      this.debited = BigInt(saved.debited)
      this.refunded = BigInt(saved.refunded)
      this.refused = saved.refused ?? 0
      for (const kind of Object.keys(this.byKind) as DebitKind[]) {
        const k = saved.byKind?.[kind]
        if (k && /^\d+$/.test(k.amount)) this.byKind[kind] = { n: k.n, amount: BigInt(k.amount) }
      }
    }
  }

  private persist(): void {
    if (!this.store) return
    const byKind = Object.fromEntries(
      Object.entries(this.byKind).map(([kind, k]) => [kind, { n: k.n, amount: k.amount.toString() }]),
    ) as SpendState['byKind']
    this.store.save({ day: this.day, debited: this.debited.toString(), refunded: this.refunded.toString(), refused: this.refused, byKind })
  }

  private roll(): void {
    const today = utcDay(this.now())
    if (today === this.day) return
    this.day = today
    this.debited = 0n
    this.refunded = 0n
    this.refused = 0
    for (const k of Object.values(this.byKind)) {
      k.n = 0
      k.amount = 0n
    }
    this.persist()
  }

  remaining(): bigint {
    this.roll()
    const left = this.limitPerDay - this.debited + this.refunded
    return left > 0n ? left : 0n
  }

  /** Reserves budget for one debit or throws SpendLimitError. Returns a release function. */
  reserve(amount: bigint, kind: DebitKind): () => void {
    return this.reserveAll([{ amount, kind }])
  }

  /**
   * Reserves every debit of one payment together (for example a charge and its network fee), or
   * none of them. Returns one release function for all of them; `keep` names debits that stay
   * counted (for example the network fee of a transaction that was included but reverted).
   */
  reserveAll(debits: readonly { amount: bigint; kind: DebitKind }[]): (keep?: (debit: { amount: bigint; kind: DebitKind }) => boolean) => void {
    this.roll()
    let total = 0n
    for (const d of debits) {
      if (d.amount <= 0n) throw new PaymentPolicyError(`refusing a non-positive ${d.kind} of ${d.amount}`)
      total += d.amount
    }
    const remaining = this.remaining()
    if (total > remaining) {
      this.refused++
      this.persist()
      throw new SpendLimitError(total, remaining)
    }
    const day = this.day
    this.debited += total
    for (const d of debits) {
      this.byKind[d.kind].n++
      this.byKind[d.kind].amount += d.amount
    }
    this.persist()
    let released = false
    return (keep) => {
      if (released || day !== this.day) return
      released = true
      for (const d of debits) {
        if (keep?.(d)) continue
        this.debited -= d.amount
        this.byKind[d.kind].n--
        this.byKind[d.kind].amount -= d.amount
      }
      this.persist()
    }
  }

  /** Budget returned by a cooperative close that refunded unspent deposit. */
  refund(amount: bigint): void {
    this.roll()
    if (amount > 0n) {
      this.refunded += amount
      this.persist()
    }
  }

  noteVoucher(channelId: string, cumulative: bigint): void {
    const current = this.vouchers.get(channelId) ?? 0n
    if (cumulative > current) this.vouchers.set(channelId, cumulative)
  }

  forgetChannel(channelId: string): void {
    this.vouchers.delete(channelId)
  }

  counters(): SpendCounters {
    this.roll()
    let authorized = 0n
    for (const v of this.vouchers.values()) authorized += v
    return {
      day: this.day,
      limit: this.limitPerDay.toString(),
      budget: this.limitPerDay.toString(),
      debited: this.debited.toString(),
      remaining: this.remaining().toString(),
      charges: this.byKind.charge.n,
      chargeAmount: this.byKind.charge.amount.toString(),
      deposits: this.byKind.deposit.n,
      depositAmount: this.byKind.deposit.amount.toString(),
      topUps: this.byKind.topUp.n,
      topUpAmount: this.byKind.topUp.amount.toString(),
      refunded: this.refunded.toString(),
      refused: this.refused,
      sessionAuthorized: authorized.toString(),
    }
  }
}
