// The deployment's shared spend budget (D-048). Fee settlement and sealed-mpp-payer draw on one limit. Fee
// settlement has priority: the payer may only reserve what is left after everything already spent, its own
// open reservations and `reserved_for_fees`, the agent's estimate of what settlement will still pay before the
// window ends (unpaid legs, the open period, app-hours until the window end, network fees).
//
// Where the limit comes from (review M4):
// - access-key mode: the customer's onchain authorization. The agent reads the key's remaining FEE_TOKEN limit
//   and period end (getRemainingLimit), and the payer's share is that remaining amount less what was spent since
//   the read started, open reservations and reserved_for_fees. The config's spendLimitPerDay is not used, so a
//   limit of any amount and a day, week or month period is followed as authorized. Until the first read, or for
//   a key that is missing, revoked or expired, the payer gets nothing. A key without limits falls back to config.
// - enclave-account mode: config settlement.spendLimitPerDay per UTC day.
// The window is the onchain period when known (Tempo periodic limits roll from authorization time), else the UTC
// day. It sets the fee-reservation horizon and the counters in the health report.
//
// Recovery of an orphaned escrow deposit (payments-8): the payer's requestClose and withdraw only pay a network fee
// and give back more, so a reservation for one may go past reserved_for_fees by a small allowance per transaction
// and per window, never past what the limit itself allows. Otherwise a limit below the fee floor would leave such a
// deposit in escrow for good.
//
// Nothing that may have left the limit is dropped (review M4): open reservations survive the window roll and are
// counted in the window they are released in; reservations the payer does not release within the TTL count as
// spent; a settlement transaction whose outcome is unknown counts as its full amount plus its fee reserve until
// its receipt shows, and a reverted one counts its network fee. The agent saves the state before it answers a
// reservation, so a restart cannot forget one.
import { randomBytes } from "node:crypto";

export const DAY_SEC = 86_400;
export const RESERVATION_TTL_SEC = 15 * 60;
export const MAX_OPEN_RESERVATIONS = 64;
/** Expired reservations are kept this long for a late release, then dropped (their amount stays counted). */
export const EXPIRED_KEEP_SEC = 2 * DAY_SEC;
export const MAX_KEPT_RESERVATIONS = 256;
/** Onchain period ends further out than this are not followed (Tempo periods are at most a few months here). */
export const MAX_PERIOD_SEC = 400 * DAY_SEC;

export interface Reservation {
  amount: string;
  at: number;
  /** Not released within the TTL: its amount counts as spent until a late release corrects it. */
  expired?: boolean;
  /** windowEnd of the window it was made in, or, once expired, the window its amount was counted in. */
  window?: number;
  /** `spent` right after the expiry counted it. */
  mark?: string;
}

/** The access key's FEE_TOKEN limit as last read onchain. `remaining` absent: the key has no limits. */
export interface OnchainLimit {
  remaining?: string;
  /** End of the key's current period (unix seconds); 0 for a one-time limit or a missing key. */
  periodEnd: number;
  readAt: number;
  /** `spent` when the read started: anything counted after that is not in `remaining`. */
  spentAtRead: string;
}

/** A settlement transaction whose receipt was not seen: counted in full until it is. */
export interface PendingFee {
  counted: string;
  /** The fees the transaction pulls when it succeeds. */
  owed: string;
  at: number;
  window: number;
  /** `spent` right after counting it. */
  mark: string;
}

export interface BudgetState {
  /** End of the current window (unix seconds). */
  windowEnd: number;
  /** True when windowEnd follows the access key's onchain period. */
  aligned: boolean;
  /** Spent by fee settlement in this window: approved fees plus network fees. */
  fees: string;
  /** Spent by the payer in this window: released `used` amounts and expired reservations. */
  payer: string;
  reservations: Record<string, Reservation>;
  /** Everything counted as spent so far, across windows (fees, payer debits, expired reservations, corrections). */
  spent?: string;
  onchain?: OnchainLimit;
  /** Network fee of the last settlement transaction, the estimate for later ones. */
  networkFeePerTx?: string;
  pendingFees?: Record<string, PendingFee>;
  /** Recovery reservations in this window that went past reserved_for_fees (payments-8). */
  recoveryOverReserve?: string;
}

/** What a reservation is for: `recovery` is the payer's recovery of an orphaned escrow deposit (payments-8). */
export type ReservePurpose = "recovery";

export type ReserveResult =
  | { ok: true; reservationId: string; remaining: string }
  | { ok: false; remaining: string; reason: "budget" | "too_many_reservations" };

export class SpendBudgetError extends Error {}
export class UnknownReservationError extends Error {}

const nextUtcMidnight = (now: number) => (Math.floor(now / DAY_SEC) + 1) * DAY_SEC;
const big = (v: string | undefined) => BigInt(v ?? "0");
const nonNeg = (v: bigint) => (v > 0n ? v : 0n);

export function emptyBudgetState(now: number): BudgetState {
  return { windowEnd: nextUtcMidnight(now), aligned: false, fees: "0", payer: "0", reservations: {}, spent: "0" };
}

export interface SpendBudgetOptions {
  /** The config limit (spendLimitPerDay): used in enclave-account mode and for a key without onchain limits. */
  limit: bigint;
  state: BudgetState;
  /** Access-key mode: the onchain authorization sets the limit, and nothing is available before it is read. */
  onchainLimit?: boolean;
  /** reserved_for_fees: what settlement will still pay until `windowEnd`, in fee-token base units. */
  feeReserve: (windowEnd: number, now: number) => bigint;
  /**
   * How far recovery reservations may go past reserved_for_fees: at most `perTx` each and `perWindow` in all per
   * window (payments-8). None without it.
   */
  recoveryAllowance?: { perTx: bigint; perWindow: bigint };
  ttlSec?: number;
  onChange?: () => void;
}

export class SpendBudget {
  readonly state: BudgetState;

  constructor(private readonly o: SpendBudgetOptions) {
    if (o.limit < 0n) throw new SpendBudgetError("negative spend limit");
    this.state = o.state;
    this.state.spent ??= (big(this.state.fees) + big(this.state.payer)).toString();
    for (const r of Object.values(this.state.reservations)) r.window ??= this.state.windowEnd;
  }

  private changed(): void {
    this.o.onChange?.();
  }

  /** Whether an amount counted when `spent` reached `mark` is still part of what the last onchain read does not cover. */
  private countedSinceRead(mark: string | undefined): boolean {
    const oc = this.state.onchain;
    return !oc || mark === undefined || big(mark) > big(oc.spentAtRead);
  }

  private addSpent(delta: bigint): void {
    this.state.spent = nonNeg(big(this.state.spent) + delta).toString();
  }

  /** The onchain period end when the last read is still current. */
  private onchainPeriodEnd(now: number): number | undefined {
    const oc = this.state.onchain;
    if (!this.o.onchainLimit || !oc || oc.remaining === undefined) return undefined;
    return oc.periodEnd > now && oc.periodEnd <= now + MAX_PERIOD_SEC ? oc.periodEnd : undefined;
  }

  /** Starts a new window when the current one has ended, expires stale reservations and prunes old ones. */
  private tick(now: number): void {
    const s = this.state;
    if (now >= s.windowEnd) {
      const periodEnd = this.onchainPeriodEnd(now);
      if (periodEnd !== undefined) {
        s.windowEnd = periodEnd;
        s.aligned = true;
      } else if (s.aligned) {
        // The onchain period ended and was not read again yet: assume a day until the next read.
        s.windowEnd += Math.ceil((now - s.windowEnd + 1) / DAY_SEC) * DAY_SEC;
      } else {
        s.windowEnd = nextUtcMidnight(now);
      }
      s.fees = "0";
      s.payer = "0";
      delete s.recoveryOverReserve;
      // Open reservations stay: what the payer spends on them counts in the window it releases them in.
      this.changed();
    }
    const ttl = this.o.ttlSec ?? RESERVATION_TTL_SEC;
    const kept: [string, Reservation][] = [];
    for (const [id, r] of Object.entries(s.reservations)) {
      if (!r.expired && now - r.at >= ttl) {
        r.expired = true;
        s.payer = (big(s.payer) + big(r.amount)).toString();
        this.addSpent(big(r.amount));
        r.mark = big(s.spent).toString();
        r.window = s.windowEnd; // the window its amount is counted in
        this.changed();
      }
      if (r.expired && now - r.at >= EXPIRED_KEEP_SEC) {
        delete s.reservations[id];
        this.changed();
      } else if (r.expired) kept.push([id, r]);
    }
    if (kept.length > MAX_KEPT_RESERVATIONS) {
      kept.sort((a, b) => a[1].at - b[1].at);
      for (const [id] of kept.slice(0, kept.length - MAX_KEPT_RESERVATIONS)) delete s.reservations[id];
      this.changed();
    }
  }

  private outstanding(): bigint {
    let sum = 0n;
    for (const r of Object.values(this.state.reservations)) if (!r.expired) sum += BigInt(r.amount);
    return sum;
  }

  /** End of the window fee priority covers: the onchain period end when current, else the local window. */
  windowEnd(now: number): number {
    this.tick(now);
    return this.onchainPeriodEnd(now) ?? this.state.windowEnd;
  }

  /** What the shared limit still allows before reservations and reserved_for_fees. */
  private headroom(): bigint {
    const oc = this.state.onchain;
    if (this.o.onchainLimit && oc?.remaining !== undefined) {
      return big(oc.remaining) - nonNeg(big(this.state.spent) - big(oc.spentAtRead));
    }
    if (this.o.onchainLimit && !oc) return 0n; // not read yet: fail closed
    return this.o.limit - big(this.state.fees) - big(this.state.payer);
  }

  /**
   * What fee settlement may still take from the config limit in this window when the agent enforces it (enclave-account
   * mode, review I6): the limit less what was spent and the payer's open reservations. Undefined in access-key mode,
   * where the chain enforces the key's limit and the payer reads it.
   */
  feeHeadroom(now: number): bigint | undefined {
    if (this.o.onchainLimit) return undefined;
    this.tick(now);
    return nonNeg(this.headroom() - this.outstanding());
  }

  /** What the payer may still reserve now. */
  available(now: number): bigint {
    this.tick(now);
    const end = this.onchainPeriodEnd(now) ?? this.state.windowEnd;
    return nonNeg(this.headroom() - this.outstanding() - this.o.feeReserve(end, now));
  }

  /**
   * Whether `reserve` would grant this amount under the current (possibly stale) reading, without mutating anything.
   * D-089 B1: the agent reads the onchain limit synchronously before authorizing a reservation the cache would let
   * through, so a decreased limit is not charged against the stale higher value.
   */
  wouldGrant(amount: bigint, now: number, purpose?: ReservePurpose): boolean {
    if (amount <= 0n) return false;
    this.tick(now);
    const open = Object.values(this.state.reservations).filter((r) => !r.expired).length;
    if (open >= MAX_OPEN_RESERVATIONS) return false;
    if (amount <= this.available(now)) return true;
    return purpose === "recovery" && this.recoveryFits(amount);
  }

  reserve(amount: bigint, now: number, purpose?: ReservePurpose): ReserveResult {
    if (amount <= 0n) throw new SpendBudgetError("amount must be positive");
    const remaining = this.available(now);
    const open = Object.values(this.state.reservations).filter((r) => !r.expired).length;
    if (open >= MAX_OPEN_RESERVATIONS) return { ok: false, remaining: remaining.toString(), reason: "too_many_reservations" };
    const overReserve = amount > remaining;
    if (overReserve && !(purpose === "recovery" && this.recoveryFits(amount))) return { ok: false, remaining: remaining.toString(), reason: "budget" };
    if (overReserve) this.state.recoveryOverReserve = (big(this.state.recoveryOverReserve) + amount).toString();
    const reservationId = `0x${randomBytes(16).toString("hex")}`;
    this.state.reservations[reservationId] = { amount: amount.toString(), at: now, window: this.state.windowEnd };
    this.changed();
    return { ok: true, reservationId, remaining: nonNeg(remaining - amount).toString() };
  }

  /** A recovery reservation past reserved_for_fees: within the allowance and within what the limit itself allows. */
  private recoveryFits(amount: bigint): boolean {
    const a = this.o.recoveryAllowance;
    if (!a || amount > a.perTx || big(this.state.recoveryOverReserve) + amount > a.perWindow) return false;
    return amount <= this.headroom() - this.outstanding();
  }

  /** Undoes a reservation that was never handed out (the state could not be saved). */
  cancel(reservationId: string): void {
    if (!(reservationId in this.state.reservations)) return;
    delete this.state.reservations[reservationId];
    this.changed();
  }

  /** The payer settles a reservation with what it actually spent (0 when the debit failed). */
  release(reservationId: string, used: bigint, now: number): { ok: true; remaining: string } {
    if (used < 0n) throw new SpendBudgetError("used must not be negative");
    this.tick(now);
    const s = this.state;
    const r = s.reservations[reservationId];
    if (!r) throw new UnknownReservationError("unknown or already released reservation");
    delete s.reservations[reservationId];
    let payer = big(s.payer) + used;
    let spent = used;
    if (r.expired) {
      // Its amount was counted as spent when it expired. In the same window the release replaces that guess;
      // after a roll the old window's count is gone, so `used` simply counts in this one. An onchain read that
      // started after the expiry already holds the chain's own number, so the guess is not taken back there.
      if (this.countedSinceRead(r.mark)) spent -= big(r.amount);
      if ((r.window ?? s.windowEnd) === s.windowEnd) payer -= big(r.amount);
    }
    s.payer = nonNeg(payer).toString();
    this.addSpent(spent);
    this.changed();
    return { ok: true, remaining: this.available(now).toString() };
  }

  /** Fee settlement spent `amount` (approved fees plus the network fee) at `now`. */
  recordFees(amount: bigint, now: number, networkFee?: bigint): void {
    this.tick(now);
    if (networkFee !== undefined && networkFee > 0n) this.state.networkFeePerTx = networkFee.toString();
    if (amount <= 0n) {
      if (networkFee !== undefined) this.changed();
      return;
    }
    this.state.fees = (big(this.state.fees) + amount).toString();
    this.addSpent(amount);
    this.changed();
  }

  /**
   * A settlement transaction was broadcast but its outcome is unknown (receipt timeout, lost response): count
   * `counted` (its fees plus the fee reserve) now, and correct it once the receipt shows (resolvePendingFee).
   */
  recordPendingFee(txHash: string, owed: bigint, counted: bigint, now: number): void {
    this.recordFees(counted, now);
    this.state.pendingFees ??= {};
    this.state.pendingFees[txHash.toLowerCase()] = { counted: counted.toString(), owed: owed.toString(), at: now, window: this.state.windowEnd, mark: big(this.state.spent).toString() };
    this.changed();
  }

  pendingFees(): Array<{ txHash: string } & PendingFee> {
    return Object.entries(this.state.pendingFees ?? {}).map(([txHash, p]) => ({ txHash, ...p }));
  }

  /** The receipt of a pending transaction showed what it really took (fees if it succeeded, plus its network fee). */
  resolvePendingFee(txHash: string, actual: bigint, now: number): void {
    this.tick(now);
    const p = this.state.pendingFees?.[txHash.toLowerCase()];
    if (!p) return;
    delete this.state.pendingFees?.[txHash.toLowerCase()];
    const delta = actual - big(p.counted);
    if (delta > 0n) {
      this.state.fees = (big(this.state.fees) + delta).toString();
      this.addSpent(delta);
    } else if (delta < 0n) {
      // Give back the overcount only where it is still counted: this window's fees, and `spent` only if an
      // onchain read that started after the count has not already replaced it with the chain's own number.
      if (p.window === this.state.windowEnd) this.state.fees = nonNeg(big(this.state.fees) + delta).toString();
      if (this.countedSinceRead(p.mark)) this.addSpent(delta);
    }
    this.changed();
  }

  /** Call before reading the onchain limit; pass the result to setOnchain with what was read. */
  beginOnchainRead(): string {
    return big(this.state.spent).toString();
  }

  /**
   * The access key's limit as read onchain: `undefined` for a key without limits (config applies); a missing,
   * revoked or expired key reads as remaining 0.
   */
  setOnchain(limit: { remaining: bigint; periodEnd: number } | undefined, spentAtRead: string, now: number): void {
    if (!this.o.onchainLimit) return;
    this.tick(now);
    const s = this.state;
    s.onchain = limit
      ? { remaining: limit.remaining.toString(), periodEnd: Number.isSafeInteger(limit.periodEnd) ? limit.periodEnd : 0, readAt: now, spentAtRead }
      : { periodEnd: 0, readAt: now, spentAtRead };
    const periodEnd = this.onchainPeriodEnd(now);
    if (periodEnd !== undefined && !(s.aligned && s.windowEnd === periodEnd)) {
      s.windowEnd = periodEnd;
      s.aligned = true;
    }
    this.changed();
  }

  /** True in access-key mode: the onchain authorization sets the limit. */
  get followsOnchain(): boolean {
    return this.o.onchainLimit === true;
  }

  /** Seconds since the onchain limit was last read (Infinity before the first read). */
  onchainAge(now: number): number {
    const oc = this.state.onchain;
    return oc ? now - oc.readAt : Number.POSITIVE_INFINITY;
  }

  /** Content-free counters for the signed health report. */
  snapshot(now: number): Record<string, string> {
    const available = this.available(now);
    const end = this.windowEnd(now);
    const oc = this.state.onchain;
    return {
      budget_limit: this.o.limit.toString(),
      budget_source: this.o.onchainLimit && oc?.remaining !== undefined ? "onchain" : this.o.onchainLimit && !oc ? "unread" : "config",
      budget_fees: this.state.fees,
      budget_payer: this.state.payer,
      budget_reserved: this.outstanding().toString(),
      budget_reservedForFees: this.o.feeReserve(end, now).toString(),
      budget_payerAvailable: available.toString(),
      budget_windowEnd: String(end),
      ...(oc?.remaining !== undefined ? { budget_onchainRemaining: oc.remaining, budget_onchainReadAt: String(oc.readAt) } : {}),
      ...(this.state.pendingFees && Object.keys(this.state.pendingFees).length > 0 ? { budget_pendingTxs: String(Object.keys(this.state.pendingFees).length) } : {}),
    };
  }
}
