import { describe, expect, it } from "vitest";
import { roundDownSignificant, roundDownSignificantDecimal } from "../src/index.js";

describe("D-065 rounding of counts sent to the platform", () => {
  it("rounds down to two significant figures", () => {
    const cases: [number, number][] = [
      [0, 0], [7, 7], [10, 10], [99, 99], [100, 100], [101, 100], [123, 120], [199, 190], [999, 990],
      [1000, 1000], [1049, 1000], [98765, 98000], [Number.MAX_SAFE_INTEGER, 9_000_000_000_000_000],
    ];
    for (const [n, want] of cases) expect(roundDownSignificant(n), String(n)).toBe(want);
    expect(roundDownSignificant(98765, 3)).toBe(98700);
    // Idempotent, so rounding twice (egress, then the agent) changes nothing.
    for (let n = 0; n < 5000; n += 7) expect(roundDownSignificant(roundDownSignificant(n))).toBe(roundDownSignificant(n));
  });

  it("rounds decimal strings of any size the same way", () => {
    expect(roundDownSignificantDecimal("0")).toBe("0");
    expect(roundDownSignificantDecimal("42")).toBe("42");
    expect(roundDownSignificantDecimal("1234567")).toBe("1200000");
    expect(roundDownSignificantDecimal("000123")).toBe("120");
    expect(roundDownSignificantDecimal("123456789012345678901234567890")).toBe("120000000000000000000000000000");
  });

  it("refuses what is not a count", () => {
    for (const n of [-1, 1.5, Number.NaN, 2 ** 53]) expect(() => roundDownSignificant(n), String(n)).toThrow(RangeError);
    for (const s of ["", "-1", "1e3", "0x10", " 1"]) expect(() => roundDownSignificantDecimal(s), s).toThrow(RangeError);
  });
});
