// The shared spend budget (D-048): the payer reserves from what fee settlement leaves, and nothing that may have
// left the limit is forgotten (review M4): window rolls, unconfirmed and reverted settlements, the onchain limit.
import { describe, expect, it } from "vitest";
import {
  DAY_SEC,
  EXPIRED_KEEP_SEC,
  emptyBudgetState,
  MAX_OPEN_RESERVATIONS,
  RESERVATION_TTL_SEC,
  SpendBudget,
  SpendBudgetError,
  UnknownReservationError,
} from "../src/payments/budget.js";

const T0 = 1_800_000_000; // 2027-01-15T08:00:00Z
const MIDNIGHT = (Math.floor(T0 / DAY_SEC) + 1) * DAY_SEC;
const make = (o: { limit?: bigint; feeReserve?: (end: number, now: number) => bigint; now?: number; onchain?: boolean } = {}) => {
  let changes = 0;
  const b = new SpendBudget({
    limit: o.limit ?? 2_000_000n,
    state: emptyBudgetState(o.now ?? T0),
    feeReserve: o.feeReserve ?? (() => 0n),
    onchainLimit: o.onchain,
    onChange: () => changes++,
  });
  return { b, changes: () => changes };
};
const id = (r: ReturnType<SpendBudget["reserve"]>) => (r as { reservationId: string }).reservationId;

describe("shared spend budget (D-048)", () => {
  it("reserves and releases against the daily limit", () => {
    const { b, changes } = make();
    const r = b.reserve(500_000n, T0);
    expect(r).toMatchObject({ ok: true, remaining: "1500000" });
    expect(id(r)).toMatch(/^0x[0-9a-f]{32}$/);
    expect(b.reserve(1_600_000n, T0)).toEqual({ ok: false, remaining: "1500000", reason: "budget" });
    // The debit cost less than reserved: the rest comes back.
    expect(b.release(id(r), 300_000n, T0)).toEqual({ ok: true, remaining: "1700000" });
    expect(() => b.release(id(r), 1n, T0)).toThrow(UnknownReservationError);
    expect(b.state).toMatchObject({ payer: "300000", fees: "0", reservations: {}, spent: "300000" });
    expect(changes()).toBeGreaterThan(0);
  });

  it("gives fee settlement priority over the whole window: the payer only gets what is left after reserved_for_fees", () => {
    let reserveForFees = 400_000n;
    const horizons: number[] = [];
    const { b } = make({
      feeReserve: (end, now) => {
        horizons.push(end - now);
        return reserveForFees;
      },
    });
    expect(b.available(T0)).toBe(1_600_000n);
    // reserved_for_fees covers everything settlement pays until the window ends (review M5).
    expect(horizons.at(-1)).toBe(MIDNIGHT - T0);
    expect(b.reserve(1_600_001n, T0)).toMatchObject({ ok: false, reason: "budget" });
    const r = b.reserve(1_600_000n, T0);
    expect(r).toMatchObject({ ok: true, remaining: "0" });
    // Settlement then pays the fees it reserved for, out of the same limit.
    b.recordFees(390_000n, T0 + 10, 2_000n);
    reserveForFees = 0n;
    b.release(id(r), 1_600_000n, T0 + 20);
    expect(b.available(T0 + 20)).toBe(10_000n);
    expect(b.state.networkFeePerTx).toBe("2000");
    expect(b.snapshot(T0 + 20)).toEqual({
      budget_limit: "2000000",
      budget_source: "config",
      budget_fees: "390000",
      budget_payer: "1600000",
      budget_reserved: "0",
      budget_reservedForFees: "0",
      budget_payerAvailable: "10000",
      budget_windowEnd: String(MIDNIGHT),
    });
    // More expected fees than budget: the payer gets nothing, never a negative amount.
    reserveForFees = 5_000_000n;
    expect(b.available(T0 + 30)).toBe(0n);
  });

  it("counts a reservation that is not released in time as spent, and corrects it on a late release", () => {
    const { b } = make();
    const r = b.reserve(700_000n, T0);
    expect(b.available(T0 + RESERVATION_TTL_SEC - 1)).toBe(1_300_000n);
    expect(b.available(T0 + RESERVATION_TTL_SEC)).toBe(1_300_000n);
    expect(b.state.payer).toBe("700000");
    expect(b.state.reservations[id(r)]?.expired).toBe(true);
    b.release(id(r), 0n, T0 + RESERVATION_TTL_SEC + 5);
    expect(b.state.payer).toBe("0");
    expect(b.available(T0 + RESERVATION_TTL_SEC + 5)).toBe(2_000_000n);
  });

  it("keeps open reservations across the window roll and counts what they spent in the window they are released in", () => {
    // Review M4 (budget-roll case 1): a deposit reserved 30 s before the roll and released after it.
    const { b } = make({ now: MIDNIGHT - 30 });
    b.recordFees(100_000n, MIDNIGHT - 40);
    const r = b.reserve(500_000n, MIDNIGHT - 30);
    expect(b.available(MIDNIGHT - 30)).toBe(1_400_000n);
    // The new window starts with no spend, but the open reservation still holds its amount.
    expect(b.available(MIDNIGHT + 5)).toBe(1_500_000n);
    expect(b.state).toMatchObject({ fees: "0", payer: "0", windowEnd: MIDNIGHT + DAY_SEC, aligned: false });
    expect(b.release(id(r), 500_000n, MIDNIGHT + 5)).toEqual({ ok: true, remaining: "1500000" });
    expect(b.state.payer).toBe("500000");
    // A reservation that expired in the old window and is released late counts its real spend in this one.
    const late = b.reserve(300_000n, MIDNIGHT + DAY_SEC - 60);
    expect(b.available(MIDNIGHT + DAY_SEC - 60 + RESERVATION_TTL_SEC)).toBe(2_000_000n - 300_000n); // rolled, expired
    expect(b.state.payer).toBe("300000");
    b.release(id(late), 200_000n, MIDNIGHT + DAY_SEC + RESERVATION_TTL_SEC);
    expect(b.state.payer).toBe("200000");
  });

  it("drops expired reservations after a while, so the state stays bounded", () => {
    const { b } = make({ limit: 10_000_000n });
    const r = b.reserve(1000n, T0);
    b.available(T0 + RESERVATION_TTL_SEC);
    expect(b.state.reservations[id(r)]?.expired).toBe(true);
    b.available(T0 + EXPIRED_KEEP_SEC);
    expect(b.state.reservations[id(r)]).toBeUndefined();
    expect(() => b.release(id(r), 1000n, T0 + EXPIRED_KEEP_SEC)).toThrow(UnknownReservationError);
  });

  it("counts a settlement whose outcome is unknown in full until its receipt shows (review M4 case 2)", () => {
    const { b } = make();
    b.recordPendingFee("0xAB", 1_200_000n, 1_250_000n, T0);
    expect(b.available(T0)).toBe(750_000n);
    expect(b.pendingFees()).toEqual([{ txHash: "0xab", counted: "1250000", owed: "1200000", at: T0, window: MIDNIGHT, mark: "1250000" }]);
    // The receipt: it succeeded and paid 1.2 USD plus a 3000 network fee.
    b.resolvePendingFee("0xab", 1_203_000n, T0 + 60);
    expect(b.pendingFees()).toEqual([]);
    expect(b.state.fees).toBe("1203000");
    expect(b.available(T0 + 60)).toBe(797_000n);
    // A reverted one only cost its network fee.
    b.recordPendingFee("0xcd", 500_000n, 520_000n, T0 + 100);
    b.resolvePendingFee("0xcd", 3_000n, T0 + 200);
    expect(b.state.fees).toBe("1206000");
    // Resolved in a later window: the old window's count is gone, this window is not reduced.
    b.recordPendingFee("0xef", 100_000n, 110_000n, MIDNIGHT - 10);
    b.resolvePendingFee("0xef", 0n, MIDNIGHT + 10);
    expect(b.state.fees).toBe("0");
  });

  it("follows the onchain limit in access-key mode: nothing before the first read, then remaining less what was spent since", () => {
    const { b } = make({ onchain: true, feeReserve: () => 100_000n });
    expect(b.available(T0)).toBe(0n);
    expect(b.reserve(1n, T0)).toMatchObject({ ok: false, reason: "budget" });
    expect(b.snapshot(T0).budget_source).toBe("unread");
    // A weekly key authorized 6 hours ago with 10 USD, 1 USD of it used: the config's 2 USD a day plays no part.
    const periodEnd = T0 - 6 * 3600 + 7 * DAY_SEC;
    let mark = b.beginOnchainRead();
    b.recordFees(50_000n, T0); // counted while the read was in flight: not in what the read returns
    b.setOnchain({ remaining: 9_000_000n, periodEnd }, mark, T0 + 1);
    expect(b.state).toMatchObject({ windowEnd: periodEnd, aligned: true });
    expect(b.windowEnd(T0 + 1)).toBe(periodEnd);
    expect(b.available(T0 + 1)).toBe(9_000_000n - 50_000n - 100_000n);
    const r = b.reserve(1_000_000n, T0 + 2);
    expect(b.available(T0 + 2)).toBe(7_850_000n);
    b.release(id(r), 400_000n, T0 + 3);
    expect(b.available(T0 + 3)).toBe(8_450_000n);
    // The next read replaces the local count with the chain's.
    mark = b.beginOnchainRead();
    b.setOnchain({ remaining: 8_550_000n, periodEnd }, mark, T0 + 60);
    expect(b.available(T0 + 60)).toBe(8_450_000n);
    expect(b.snapshot(T0 + 60)).toMatchObject({ budget_source: "onchain", budget_onchainRemaining: "8550000", budget_windowEnd: String(periodEnd) });
    // An unconfirmed settlement counted before that read is not given back on top of the chain's number.
    b.recordPendingFee("0x01", 1_000_000n, 1_100_000n, T0 + 70);
    mark = b.beginOnchainRead();
    b.setOnchain({ remaining: 7_450_000n, periodEnd }, mark, T0 + 80); // it landed: the chain shows it
    b.resolvePendingFee("0x01", 1_003_000n, T0 + 90);
    expect(b.available(T0 + 90)).toBe(7_350_000n);
    // Revoked or missing key: remaining 0. A key without limits: the config limit applies.
    b.setOnchain({ remaining: 0n, periodEnd: 0 }, b.beginOnchainRead(), T0 + 100);
    expect(b.available(T0 + 100)).toBe(0n);
    b.setOnchain(undefined, b.beginOnchainRead(), T0 + 110);
    expect(b.snapshot(T0 + 110).budget_source).toBe("config");
    expect(b.onchainAge(T0 + 170)).toBe(60);
  });

  it("an expired reservation released after a newer onchain read is not given back", () => {
    const { b } = make({ onchain: true });
    b.setOnchain({ remaining: 2_000_000n, periodEnd: T0 + DAY_SEC }, b.beginOnchainRead(), T0);
    const r = b.reserve(700_000n, T0);
    expect(b.available(T0 + RESERVATION_TTL_SEC)).toBe(1_300_000n);
    // The payer did spend it; the chain shows it at the next read.
    b.setOnchain({ remaining: 1_300_000n, periodEnd: T0 + DAY_SEC }, b.beginOnchainRead(), T0 + RESERVATION_TTL_SEC + 10);
    b.release(id(r), 700_000n, T0 + RESERVATION_TTL_SEC + 20);
    expect(b.available(T0 + RESERVATION_TTL_SEC + 20)).toBe(600_000n); // conservative: counted twice until the next read
  });

  it("rolls with the onchain period and assumes a day when the period ended before a new read", () => {
    const { b } = make({ onchain: true });
    const periodEnd = T0 + 3600;
    b.setOnchain({ remaining: 1_000_000n, periodEnd }, b.beginOnchainRead(), T0);
    b.recordFees(100_000n, T0 + 10);
    expect(b.available(periodEnd)).toBe(900_000n); // the stale reading only gets more conservative
    expect(b.state).toMatchObject({ windowEnd: periodEnd + DAY_SEC, fees: "0", aligned: true });
    b.setOnchain({ remaining: 2_000_000n, periodEnd: periodEnd + DAY_SEC }, b.beginOnchainRead(), periodEnd + 5);
    expect(b.available(periodEnd + 5)).toBe(2_000_000n);
    // Implausible period ends are not followed.
    b.setOnchain({ remaining: 2_000_000n, periodEnd: periodEnd + 500 * DAY_SEC }, b.beginOnchainRead(), periodEnd + 6);
    expect(b.windowEnd(periodEnd + 6)).toBe(periodEnd + DAY_SEC);
  });

  it("starts a new window at UTC midnight in config mode", () => {
    const { b } = make();
    b.recordFees(100_000n, T0);
    b.reserve(200_000n, T0);
    expect(b.available(MIDNIGHT - 1)).toBe(1_700_000n); // the reservation expired hours ago: counted as spent
    expect(b.available(MIDNIGHT)).toBe(2_000_000n);
    expect(b.state).toMatchObject({ fees: "0", payer: "0", windowEnd: MIDNIGHT + DAY_SEC, aligned: false });
    // setOnchain is ignored outside access-key mode.
    b.setOnchain({ remaining: 1n, periodEnd: MIDNIGHT + 60 }, b.beginOnchainRead(), MIDNIGHT + 1);
    expect(b.state.onchain).toBeUndefined();
  });

  it("bounds open reservations, refuses non-positive amounts, and can cancel one that was never handed out", () => {
    const { b } = make({ limit: 10_000_000n });
    for (let i = 0; i < MAX_OPEN_RESERVATIONS; i++) expect(b.reserve(1n, T0).ok).toBe(true);
    expect(b.reserve(1n, T0)).toMatchObject({ ok: false, reason: "too_many_reservations" });
    expect(() => b.reserve(0n, T0)).toThrow(SpendBudgetError);
    expect(() => b.release("0x00", -1n, T0)).toThrow(SpendBudgetError);
    const first = Object.keys(b.state.reservations)[0] as string;
    b.cancel(first);
    expect(b.reserve(1n, T0).ok).toBe(true);
  });

  it("reads state written before these fields", () => {
    const state = { windowEnd: MIDNIGHT, aligned: false, fees: "100", payer: "200", reservations: { "0xaa": { amount: "50", at: T0 } } };
    const b = new SpendBudget({ limit: 1000n, state, feeReserve: () => 0n });
    expect(b.state).toMatchObject({ spent: "300", reservations: { "0xaa": { window: MIDNIGHT } } });
    expect(b.available(T0)).toBe(650n);
  });
});

// payments-8: a limit below the app-hour floor leaves the payer 0 for the whole period, so the payer's recovery of an
// orphaned escrow deposit (a requestClose or withdraw network fee) was refused at every hour and the deposit stayed in
// escrow. A `recovery` reservation may go past reserved_for_fees by a small allowance, never past the limit itself.
describe("payments-8: recovery reservations below the fee floor", () => {
  const ALLOWANCE = { perTx: 10_000n, perWindow: 50_000n };
  // reserved_for_fees as Agent.feeReserve computes it for crm, coding-agent and internal-tools (0.15 USD per hour until
  // the window ends), with nothing unpaid yet: 3.60 USD a day against a 2 USD limit.
  const floor = (windowEnd: number, now: number) => (150_000n * BigInt(Math.max(0, windowEnd - now)) + 3599n) / 3600n;
  const onchain = (recoveryAllowance?: typeof ALLOWANCE) => {
    const b = new SpendBudget({ limit: 2_000_000n, state: emptyBudgetState(T0), onchainLimit: true, feeReserve: floor, recoveryAllowance });
    b.setOnchain({ remaining: 2_000_000n, periodEnd: T0 + DAY_SEC }, b.beginOnchainRead(), T0);
    return b;
  };

  it("lets a 0.01 USD recovery reservation through at every hour of the period, while ordinary ones are refused", () => {
    const b = onchain(ALLOWANCE);
    const refused: number[] = [];
    let granted = 0;
    for (let h = 0; h < 24; h++) {
      const now = T0 + h * 3600;
      // Fees paid so far this period lower the key's remaining limit (only the hours already accrued).
      b.setOnchain({ remaining: 2_000_000n - BigInt(Math.min(h, 13)) * 150_000n, periodEnd: T0 + DAY_SEC }, b.beginOnchainRead(), now);
      expect(b.reserve(10_000n, now)).toMatchObject({ ok: false, reason: "budget" });
      const r = b.reserve(10_000n, now, "recovery");
      if (!r.ok) {
        refused.push(h);
        continue;
      }
      granted++;
      b.release(r.reservationId, 10_000n, now);
    }
    // Five transactions per window (0.05 USD), then the allowance is used up until the window rolls.
    expect(granted).toBe(5);
    expect(refused).toHaveLength(19);
    expect(b.state.recoveryOverReserve).toBe("50000");
    const next = T0 + DAY_SEC + 60;
    b.setOnchain({ remaining: 2_000_000n, periodEnd: T0 + 2 * DAY_SEC }, b.beginOnchainRead(), next);
    expect(b.state.recoveryOverReserve).toBeUndefined();
    expect(b.reserve(10_000n, next, "recovery").ok).toBe(true);
  });

  it("refuses a recovery reservation above the per-transaction allowance or above what the limit allows", () => {
    const b = onchain(ALLOWANCE);
    expect(b.reserve(10_001n, T0, "recovery")).toMatchObject({ ok: false, reason: "budget" });
    b.setOnchain({ remaining: 5_000n, periodEnd: T0 + DAY_SEC }, b.beginOnchainRead(), T0);
    expect(b.reserve(5_001n, T0, "recovery")).toMatchObject({ ok: false, reason: "budget" });
    expect(b.reserve(5_000n, T0, "recovery")).toMatchObject({ ok: true, remaining: "0" });
    // Open reservations count against the limit too.
    expect(b.reserve(1n, T0, "recovery")).toMatchObject({ ok: false });
  });

  it("without an allowance a recovery reservation is an ordinary one, and one that fits needs no allowance", () => {
    expect(onchain().reserve(10_000n, T0, "recovery")).toMatchObject({ ok: false, reason: "budget" });
    const { b } = make({ limit: 2_000_000n });
    expect(b.reserve(10_000n, T0, "recovery").ok).toBe(true);
    expect(b.state.recoveryOverReserve).toBeUndefined();
  });
});
