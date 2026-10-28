// The deployment's shared daily spend budget (D-048). Fee settlement and sealed-mpp-payer draw on one
// limit: the customer's access-key spending limit (config settlement.spendLimitPerDay, also written to
// the payer as SPEND_LIMIT_PER_DAY). Fee settlement has priority: the payer may only reserve what is
// left after everything spent in the window, its own open reservations and `reserved_for_fees`, the
// agent's estimate of what the next settlement will pay (unpaid legs, the open period, app-hours until
// the next settlement, network fees).
//
// The window is the access key's own period when the agent can read it onchain (Tempo periodic limits
// roll from authorization time, not at midnight), else the UTC day. Reservations the payer does not
// release within the TTL count as spent: a payer that crashed after paying must not free budget it
// used. State lives in the agent's state file on the encrypted disk, so a restart does not reset it.
import { randomBytes } from "node:crypto";

export const DAY_SEC = 86_400;
export const RESERVATION_TTL_SEC = 15 * 60;
export const MAX_OPEN_RESERVATIONS = 64;

export interface Reservation {
  amount: string;
  at: number;
  /** Not released within the TTL: its amount counts as spent until a late release corrects it. */
  expired?: boolean;
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
}

export type ReserveResult =
  | { ok: true; reservationId: string; remaining: string }
  | { ok: false; remaining: string; reason: "budget" | "too_many_reservations" };

export class SpendBudgetError extends Error {}
export class UnknownReservationError extends Error {}

const nextUtcMidnight = (now: number) => (Math.floor(now / DAY_SEC) + 1) * DAY_SEC;

export function emptyBudgetState(now: number): BudgetState {
  return { windowEnd: nextUtcMidnight(now), aligned: false, fees: "0", payer: "0", reservations: {} };
}

export interface SpendBudgetOptions {
  limit: bigint;
  state: BudgetState;
  /** reserved_for_fees: what the next settlement is expected to pay, in fee-token base units. */
  feeReserve: () => bigint;
  ttlSec?: number;
  onChange?: () => void;
}

export class SpendBudget {
  readonly state: BudgetState;

  constructor(private readonly o: SpendBudgetOptions) {
    if (o.limit < 0n) throw new SpendBudgetError("negative spend limit");
    this.state = o.state;
  }

  private changed(): void {
    this.o.onChange?.();
  }

  /** Starts a new window when the current one has ended, and expires stale reservations. */
  private tick(now: number): void {
    const s = this.state;
    if (now >= s.windowEnd) {
      s.windowEnd = s.aligned ? s.windowEnd + Math.ceil((now - s.windowEnd + 1) / DAY_SEC) * DAY_SEC : nextUtcMidnight(now);
      s.fees = "0";
      s.payer = "0";
      s.reservations = {};
      this.changed();
    }
    const ttl = this.o.ttlSec ?? RESERVATION_TTL_SEC;
    for (const r of Object.values(s.reservations)) {
      if (!r.expired && now - r.at >= ttl) {
        r.expired = true;
        s.payer = (BigInt(s.payer) + BigInt(r.amount)).toString();
        this.changed();
      }
    }
  }

  private outstanding(): bigint {
    let sum = 0n;
    for (const r of Object.values(this.state.reservations)) if (!r.expired) sum += BigInt(r.amount);
    return sum;
  }

  /** What the payer may still reserve now. */
  available(now: number): bigint {
    this.tick(now);
    const left = this.o.limit - BigInt(this.state.fees) - BigInt(this.state.payer) - this.outstanding() - this.o.feeReserve();
    return left > 0n ? left : 0n;
  }

  reserve(amount: bigint, now: number): ReserveResult {
    if (amount <= 0n) throw new SpendBudgetError("amount must be positive");
    const remaining = this.available(now);
    const open = Object.values(this.state.reservations).filter((r) => !r.expired).length;
    if (open >= MAX_OPEN_RESERVATIONS) return { ok: false, remaining: remaining.toString(), reason: "too_many_reservations" };
    if (amount > remaining) return { ok: false, remaining: remaining.toString(), reason: "budget" };
    const reservationId = `0x${randomBytes(16).toString("hex")}`;
    this.state.reservations[reservationId] = { amount: amount.toString(), at: now };
    this.changed();
    return { ok: true, reservationId, remaining: (remaining - amount).toString() };
  }

  /** The payer settles a reservation with what it actually spent (0 when the debit failed). */
  release(reservationId: string, used: bigint, now: number): { ok: true; remaining: string } {
    if (used < 0n) throw new SpendBudgetError("used must not be negative");
    this.tick(now);
    const r = this.state.reservations[reservationId];
    if (!r) throw new UnknownReservationError("unknown or already released reservation");
    delete this.state.reservations[reservationId];
    let payer = BigInt(this.state.payer) + used;
    if (r.expired) payer -= BigInt(r.amount);
    this.state.payer = (payer > 0n ? payer : 0n).toString();
    this.changed();
    return { ok: true, remaining: this.available(now).toString() };
  }

  /** Fee settlement spent `amount` (approved fees plus the network fee) at `now`. */
  recordFees(amount: bigint, now: number): void {
    if (amount <= 0n) return;
    this.tick(now);
    this.state.fees = (BigInt(this.state.fees) + amount).toString();
    this.changed();
  }

  /** Follows the access key's onchain period end (Tempo periodic limits roll from authorization time). */
  alignWindow(periodEnd: number, now: number): void {
    this.tick(now);
    if (!Number.isSafeInteger(periodEnd) || periodEnd <= now || periodEnd > now + DAY_SEC) return;
    if (this.state.aligned && this.state.windowEnd === periodEnd) return;
    this.state.windowEnd = periodEnd;
    this.state.aligned = true;
    this.changed();
  }

  /** Content-free counters for the signed health report. */
  snapshot(now: number): Record<string, string> {
    const available = this.available(now);
    return {
      budget_limit: this.o.limit.toString(),
      budget_fees: this.state.fees,
      budget_payer: this.state.payer,
      budget_reserved: this.outstanding().toString(),
      budget_reservedForFees: this.o.feeReserve().toString(),
      budget_payerAvailable: available.toString(),
      budget_windowEnd: String(this.state.windowEnd),
    };
  }
}
