/**
 * Client-side spend guard. Every debit of the customer's money (a per-request charge, a
 * channel deposit, a channel top-up) must reserve budget here before its credential leaves
 * the payer. The budget is the daily limit (SPEND_LIMIT_PER_DAY) per UTC day; refunds from
 * cooperative channel closes give budget back. The protocol's own access-key limit is the
 * hard cap; this guard keeps us well inside it and lets us refuse before signing.
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

export class SpendGuard {
  private day: string
  private debited = 0n
  private refunded = 0n
  private refused = 0
  private readonly byKind = { charge: { n: 0, amount: 0n }, deposit: { n: 0, amount: 0n }, topUp: { n: 0, amount: 0n } }
  private readonly vouchers = new Map<string, bigint>()

  constructor(
    readonly limitPerDay: bigint,
    private readonly now: () => number = Date.now,
  ) {
    if (limitPerDay < 0n) throw new Error('negative spend limit')
    this.day = utcDay(this.now())
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
  }

  remaining(): bigint {
    this.roll()
    const left = this.limitPerDay - this.debited + this.refunded
    return left > 0n ? left : 0n
  }

  /** Reserves budget for one debit or throws SpendLimitError. Returns a release function. */
  reserve(amount: bigint, kind: DebitKind): () => void {
    this.roll()
    if (amount <= 0n) throw new PaymentPolicyError(`refusing a non-positive ${kind} of ${amount}`)
    const remaining = this.remaining()
    if (amount > remaining) {
      this.refused++
      throw new SpendLimitError(amount, remaining)
    }
    const day = this.day
    this.debited += amount
    this.byKind[kind].n++
    this.byKind[kind].amount += amount
    let released = false
    return () => {
      if (released || day !== this.day) return
      released = true
      this.debited -= amount
      this.byKind[kind].n--
      this.byKind[kind].amount -= amount
    }
  }

  /** Budget returned by a cooperative close that refunded unspent deposit. */
  refund(amount: bigint): void {
    this.roll()
    if (amount > 0n) this.refunded += amount
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
