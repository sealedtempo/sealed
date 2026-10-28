import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * Client-side spend guard. Every debit of the customer's money (a per-request charge, a
 * channel deposit, a channel top-up) must reserve budget here before its credential leaves
 * the payer. The budget is a share of the daily limit (SPEND_LIMIT_PER_DAY) per UTC day: the
 * agent's fee payments count against the same onchain limit (D-026), so part of it stays
 * reserved for them. Refunds from cooperative channel closes give budget back. The day's
 * debits are persisted, so a restart (or a crash loop) does not reset the budget. The
 * protocol's own access-key limit is the hard cap in access-key mode.
 */
export class SpendLimitError extends Error {
  constructor(
    readonly requested: bigint,
    readonly remaining: bigint,
  ) {
    super(`daily spend limit reached: requested ${requested}, remaining ${remaining} base units`)
    this.name = 'SpendLimitError'
  }
}

export class PaymentPolicyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PaymentPolicyError'
  }
}

export type DebitKind = 'charge' | 'deposit' | 'topUp'

export type SpendCounters = {
  day: string
  limit: string
  /** The part of the limit the payer may spend on the relay. */
  budget: string
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

export type SpendGuardOptions = { store?: SpendStore; shareBps?: number }

export class SpendGuard {
  private day: string
  private debited = 0n
  private refunded = 0n
  private refused = 0
  private readonly byKind = { charge: { n: 0, amount: 0n }, deposit: { n: 0, amount: 0n }, topUp: { n: 0, amount: 0n } }
  private readonly vouchers = new Map<string, bigint>()
  /** What the payer may spend per day: limitPerDay x shareBps / 10000. */
  readonly budgetPerDay: bigint
  private readonly store: SpendStore | undefined

  constructor(
    readonly limitPerDay: bigint,
    private readonly now: () => number = Date.now,
    options: SpendGuardOptions = {},
  ) {
    if (limitPerDay < 0n) throw new Error('negative spend limit')
    const share = options.shareBps ?? 10_000
    if (!Number.isInteger(share) || share < 0 || share > 10_000) throw new Error('spend share must be 0..10000 basis points')
    this.budgetPerDay = (limitPerDay * BigInt(share)) / 10_000n
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
    const left = this.budgetPerDay - this.debited + this.refunded
    return left > 0n ? left : 0n
  }

  /** Reserves budget for one debit or throws SpendLimitError. Returns a release function. */
  reserve(amount: bigint, kind: DebitKind): () => void {
    this.roll()
    if (amount <= 0n) throw new PaymentPolicyError(`refusing a non-positive ${kind} of ${amount}`)
    const remaining = this.remaining()
    if (amount > remaining) {
      this.refused++
      this.persist()
      throw new SpendLimitError(amount, remaining)
    }
    const day = this.day
    this.debited += amount
    this.byKind[kind].n++
    this.byKind[kind].amount += amount
    this.persist()
    let released = false
    return () => {
      if (released || day !== this.day) return
      released = true
      this.debited -= amount
      this.byKind[kind].n--
      this.byKind[kind].amount -= amount
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
      budget: this.budgetPerDay.toString(),
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
