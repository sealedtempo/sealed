import { SpendLimitError } from './spend-guard.js'

type FetchLike = (input: string, init: RequestInit) => Promise<Response>

/**
 * The shared daily budget could not be consulted (sealed-agent unreachable, not ready, or it
 * did not understand the request). The payer then refuses to pay: spending without a
 * reservation could take budget that fee settlement needs (D-048).
 */
export class BudgetUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BudgetUnavailableError'
  }
}

/** One reservation in sealed-agent's shared budget. */
export type SharedReservation = { id: string; amount: bigint; remaining?: bigint }

/**
 * The daily budget the payer shares with the agent's fee settlement (D-048). `reserve` either
 * returns a reservation or throws SpendLimitError (refused for lack of budget) or
 * BudgetUnavailableError. `release` reports what the reservation was actually used for and
 * never throws.
 */
export interface SpendBudget {
  reserve(amount: bigint): Promise<SharedReservation>
  release(reservation: SharedReservation, used: bigint): Promise<void>
}

export type SharedBudgetState = {
  /** What the agent last said the payer may still reserve today, in base units. */
  remaining?: string
  checkedAt?: number
  /** Releases that failed and are being retried. */
  pendingReleases: number
  lastError?: string
}

export type AgentSpendBudgetDeps = {
  /** sealed-agent's local API, for example http://sealed-agent:7070. */
  agentUrl: string
  fetch?: FetchLike
  /** Per-call timeout. Default 5000 ms. */
  timeoutMs?: number
  /** Delays between release retries. Default 1 s, 5 s, 30 s, 2 min, 10 min. */
  retryDelaysMs?: number[]
  now?: () => number
  log?: (event: Record<string, unknown>) => void
}

const MAX_RESERVATION_ID = 128

function decimal(value: unknown): bigint | undefined {
  if (typeof value === 'string' && /^\d{1,78}$/.test(value)) return BigInt(value)
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value)
  return undefined
}

/**
 * Client of sealed-agent's shared spend budget (brief item 21, D-048):
 *
 *   POST /v1/spend/reserve {"amount":"<base units>"}  ->  {"ok":true,"reservationId":"…","remaining":"…"}
 *                                                        {"ok":false,"remaining":"…","reason"?} when refused
 *   POST /v1/spend/release {"reservationId":"…","used":"<base units>"}
 *
 * Amounts are decimal strings of FEE_TOKEN base units (INTERFACES conventions). The agent keeps
 * the next settlement's estimated fees out of what it lets the payer reserve, so fee settlement
 * has priority. A release that fails is retried in the background; until it lands the agent
 * keeps the whole reservation counted, which can only make the payer spend less.
 */
export class AgentSpendBudget implements SpendBudget {
  private readonly current: SharedBudgetState = { pendingReleases: 0 }
  private readonly retries = new Set<NodeJS.Timeout>()
  private readonly now: () => number

  constructor(private readonly deps: AgentSpendBudgetDeps) {
    this.now = deps.now ?? (() => Math.floor(Date.now() / 1000))
  }

  state(): SharedBudgetState {
    return { ...this.current }
  }

  async reserve(amount: bigint): Promise<SharedReservation> {
    if (amount <= 0n) throw new BudgetUnavailableError(`refusing to reserve a non-positive amount ${amount}`)
    const { status, json } = await this.call('/v1/spend/reserve', { amount: amount.toString() }).catch((error: Error) => {
      this.current.lastError = error.message
      throw new BudgetUnavailableError(`sealed-agent spend budget unreachable: ${error.message}`)
    })
    const body = (json ?? {}) as { ok?: unknown; reservationId?: unknown; remaining?: unknown; reason?: unknown; error?: unknown }
    const remaining = decimal(body.remaining)
    if (status >= 500 || status === 400 || status === 401 || status === 403 || status === 404) {
      const detail = typeof body.error === 'string' ? `: ${body.error.slice(0, 200)}` : ''
      this.current.lastError = `HTTP ${status}${detail}`
      throw new BudgetUnavailableError(`sealed-agent spend budget answered HTTP ${status}${detail}`)
    }
    if (body.ok === false) {
      this.note(remaining)
      const reason = typeof body.reason === 'string' && /^[a-z_]{1,40}$/.test(body.reason) && body.reason !== 'budget' ? body.reason : undefined
      throw new SpendLimitError(amount, remaining ?? 0n, 'shared', reason)
    }
    const id = body.reservationId
    if (status < 200 || status > 299 || body.ok !== true || typeof id !== 'string' || id.length === 0 || id.length > MAX_RESERVATION_ID) {
      this.current.lastError = `unexpected reserve response (HTTP ${status})`
      throw new BudgetUnavailableError(`sealed-agent spend budget gave an unexpected reserve response (HTTP ${status})`)
    }
    this.note(remaining)
    return { id, amount, remaining }
  }

  /**
   * Reports what a reservation was used for (0 when the payment never left or was refused).
   * The first attempt is awaited, so a refused payment's budget is back before mppx retries.
   */
  async release(reservation: SharedReservation, used: bigint): Promise<void> {
    const capped = used < 0n ? 0n : used > reservation.amount ? reservation.amount : used
    if (await this.tryRelease(reservation.id, capped)) return
    this.current.pendingReleases++
    this.scheduleRetry(reservation.id, capped, 0)
  }

  /** Stops background retries (shutdown). */
  stop(): void {
    for (const timer of this.retries) clearTimeout(timer)
    this.retries.clear()
  }

  private note(remaining: bigint | undefined): void {
    this.current.checkedAt = this.now()
    this.current.lastError = undefined
    if (remaining !== undefined) this.current.remaining = remaining.toString()
  }

  private scheduleRetry(id: string, used: bigint, attempt: number): void {
    const delays = this.deps.retryDelaysMs ?? [1_000, 5_000, 30_000, 120_000, 600_000]
    if (attempt >= delays.length) {
      this.current.pendingReleases--
      this.deps.log?.({ event: 'spend_release_abandoned', reservationId: id, used: used.toString() })
      return
    }
    const timer = setTimeout(async () => {
      this.retries.delete(timer)
      if (await this.tryRelease(id, used)) this.current.pendingReleases--
      else this.scheduleRetry(id, used, attempt + 1)
    }, delays[attempt])
    timer.unref?.()
    this.retries.add(timer)
  }

  private async tryRelease(id: string, used: bigint): Promise<boolean> {
    try {
      const { status } = await this.call('/v1/spend/release', { reservationId: id, used: used.toString() })
      // 404: the agent no longer knows the reservation (expired or already released); nothing to retry.
      if ((status >= 200 && status <= 299) || status === 404) return true
      this.current.lastError = `release HTTP ${status}`
    } catch (error) {
      this.current.lastError = (error as Error).message
    }
    this.deps.log?.({ event: 'spend_release_failed', reservationId: id, detail: this.current.lastError })
    return false
  }

  private async call(path: string, body: Record<string, string>): Promise<{ status: number; json: unknown }> {
    const res = await (this.deps.fetch ?? fetch)(`${this.deps.agentUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.deps.timeoutMs ?? 5_000),
    })
    const text = await res.text()
    let json: unknown
    try {
      json = text ? JSON.parse(text) : undefined
    } catch {
      json = undefined
    }
    return { status: res.status, json }
  }
}
