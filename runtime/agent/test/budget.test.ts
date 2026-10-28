// The shared daily spend budget (D-048): the payer reserves from what fee settlement leaves.
import { describe, expect, it } from "vitest";
import { DAY_SEC, emptyBudgetState, MAX_OPEN_RESERVATIONS, RESERVATION_TTL_SEC, SpendBudget, SpendBudgetError, UnknownReservationError } from "../src/payments/budget.js";

const T0 = 1_800_000_000; // 2027-01-15T08:00:00Z
const make = (o: { limit?: bigint; feeReserve?: () => bigint; now?: number } = {}) => {
  let changes = 0;
  const b = new SpendBudget({
    limit: o.limit ?? 2_000_000n,
    state: emptyBudgetState(o.now ?? T0),
    feeReserve: o.feeReserve ?? (() => 0n),
    onChange: () => changes++,
  });
  return { b, changes: () => changes };
};

describe("shared spend budget (D-048)", () => {
  it("reserves and releases against the daily limit", () => {
    const { b, changes } = make();
    const r = b.reserve(500_000n, T0);
    expect(r).toMatchObject({ ok: true, remaining: "1500000" });
    expect((r as { reservationId: string }).reservationId).toMatch(/^0x[0-9a-f]{32}$/);
    expect(b.reserve(1_600_000n, T0)).toEqual({ ok: false, remaining: "1500000", reason: "budget" });
    // The debit cost less than reserved: the rest comes back.
    expect(b.release((r as { reservationId: string }).reservationId, 300_000n, T0)).toEqual({ ok: true, remaining: "1700000" });
    expect(() => b.release((r as { reservationId: string }).reservationId, 1n, T0)).toThrow(UnknownReservationError);
    expect(b.state).toMatchObject({ payer: "300000", fees: "0", reservations: {} });
    expect(changes()).toBeGreaterThan(0);
  });

  it("gives fee settlement priority: the payer only gets what is left after reserved_for_fees", () => {
    let reserveForFees = 400_000n;
    const { b } = make({ feeReserve: () => reserveForFees });
    expect(b.available(T0)).toBe(1_600_000n);
    expect(b.reserve(1_600_001n, T0)).toMatchObject({ ok: false, reason: "budget" });
    const r = b.reserve(1_600_000n, T0) as { reservationId: string };
    expect(r).toMatchObject({ ok: true, remaining: "0" });
    // Settlement then pays the fees it reserved for, out of the same limit.
    b.recordFees(390_000n, T0 + 10);
    reserveForFees = 0n;
    b.release(r.reservationId, 1_600_000n, T0 + 20);
    expect(b.available(T0 + 20)).toBe(10_000n);
    expect(b.snapshot(T0 + 20)).toEqual({
      budget_limit: "2000000",
      budget_fees: "390000",
      budget_payer: "1600000",
      budget_reserved: "0",
      budget_reservedForFees: "0",
      budget_payerAvailable: "10000",
      budget_windowEnd: String((Math.floor(T0 / DAY_SEC) + 1) * DAY_SEC),
    });
    // More expected fees than budget: the payer gets nothing, never a negative amount.
    reserveForFees = 5_000_000n;
    expect(b.available(T0 + 30)).toBe(0n);
  });

  it("counts a reservation that is not released in time as spent, and corrects it on a late release", () => {
    const { b } = make();
    const r = b.reserve(700_000n, T0) as { reservationId: string };
    expect(b.available(T0 + RESERVATION_TTL_SEC - 1)).toBe(1_300_000n);
    expect(b.available(T0 + RESERVATION_TTL_SEC)).toBe(1_300_000n);
    expect(b.state.payer).toBe("700000");
    expect(b.state.reservations[r.reservationId]?.expired).toBe(true);
    b.release(r.reservationId, 0n, T0 + RESERVATION_TTL_SEC + 5);
    expect(b.state.payer).toBe("0");
    expect(b.available(T0 + RESERVATION_TTL_SEC + 5)).toBe(2_000_000n);
  });

  it("starts a new window at UTC midnight, or at the access key's period end once aligned", () => {
    const { b } = make();
    b.recordFees(100_000n, T0);
    b.reserve(200_000n, T0);
    const midnight = (Math.floor(T0 / DAY_SEC) + 1) * DAY_SEC;
    expect(b.available(midnight - 1)).toBe(1_700_000n);
    expect(b.available(midnight)).toBe(2_000_000n);
    expect(b.state).toMatchObject({ fees: "0", payer: "0", reservations: {}, windowEnd: midnight + DAY_SEC, aligned: false });
    // Tempo periodic limits roll from authorization time: follow the onchain period end.
    const periodEnd = midnight + 14 * 3600;
    b.recordFees(50_000n, midnight + 10);
    b.alignWindow(periodEnd, midnight + 10);
    expect(b.state).toMatchObject({ windowEnd: periodEnd, aligned: true, fees: "50000" });
    expect(b.available(periodEnd)).toBe(2_000_000n);
    expect(b.state.windowEnd).toBe(periodEnd + DAY_SEC);
    // Stale or implausible period ends are ignored.
    b.alignWindow(periodEnd - 5, periodEnd + 1);
    b.alignWindow(periodEnd + 3 * DAY_SEC, periodEnd + 1);
    expect(b.state.windowEnd).toBe(periodEnd + DAY_SEC);
  });

  it("bounds open reservations and refuses non-positive amounts", () => {
    const { b } = make({ limit: 10_000_000n });
    for (let i = 0; i < MAX_OPEN_RESERVATIONS; i++) expect(b.reserve(1n, T0).ok).toBe(true);
    expect(b.reserve(1n, T0)).toMatchObject({ ok: false, reason: "too_many_reservations" });
    expect(() => b.reserve(0n, T0)).toThrow(SpendBudgetError);
    expect(() => b.release("0x00", -1n, T0)).toThrow(SpendBudgetError);
  });
});
