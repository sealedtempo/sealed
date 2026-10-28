import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseDefaults } from "../src/defaults.js";
import { UsageUnit } from "../src/eip712.js";
import { feeScheduleFromDefaults, maxQuantityWithinFee, priceQuantity, priceRuleFor } from "../src/pricing.js";

const defaults = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"), { testOverrides: false });
const schedule = feeScheduleFromDefaults(defaults);

describe("pricing (INTERFACES 4.2)", () => {
  it("tokens: floor(q * 200000 / 1e6)", () => {
    const rule = priceRuleFor(schedule, "llm-gateway", "tokens");
    expect(rule).toEqual({ unit: UsageUnit.tokens, price: 200_000n, per: 1_000_000n });
    expect(priceQuantity(1_000_000n, rule)).toEqual({ fee: 200_000n, carry: 0n });
    expect(priceQuantity(4n, rule)).toEqual({ fee: 0n, carry: 800_000n });
    expect(priceQuantity(1n, rule, 800_000n)).toEqual({ fee: 1n, carry: 0n });
  });
  it("pages: floor(q * 200000 / 1000)", () => {
    const rule = priceRuleFor(schedule, "scraper", "pages");
    expect(priceQuantity(1n, rule)).toEqual({ fee: 200n, carry: 0n });
    expect(priceQuantity(1000n, rule)).toEqual({ fee: 200_000n, carry: 0n });
  });
  it("app_hour: quantity in seconds priced per hour, per app", () => {
    const crm = priceRuleFor(schedule, "crm", "app_hour");
    expect(priceQuantity(3600n, crm)).toEqual({ fee: 50_000n, carry: 0n });
    expect(priceQuantity(1n, crm)).toEqual({ fee: 13n, carry: 3200n });
    expect(priceRuleFor(schedule, "llm-gateway", UsageUnit.app_hour).price).toBe(0n);
    expect(priceRuleFor(schedule, "unknown-app", "app_hour").price).toBe(0n);
  });
  it("carry makes split periods sum to the unsplit fee", () => {
    const rule = priceRuleFor(schedule, "crm", "app_hour");
    let carry = 0n;
    let total = 0n;
    for (let i = 0; i < 3600; i++) {
      const p = priceQuantity(1n, rule, carry);
      total += p.fee;
      carry = p.carry;
    }
    expect(total).toBe(priceQuantity(3600n, rule).fee);
  });
  it("maxQuantityWithinFee is the largest quantity under a cap", () => {
    const rule = priceRuleFor(schedule, "llm-gateway", "tokens");
    for (const carry of [0n, 1n, 999_999n]) {
      for (const cap of [0n, 1n, 5_000_000n]) {
        const q = maxQuantityWithinFee(rule, carry, cap) as bigint;
        expect(priceQuantity(q, rule, carry).fee <= cap).toBe(true);
        expect(priceQuantity(q + 1n, rule, carry).fee > cap).toBe(true);
      }
    }
    expect(maxQuantityWithinFee(priceRuleFor(schedule, "llm-gateway", "app_hour"), 0n, 10n)).toBeNull();
  });
});
