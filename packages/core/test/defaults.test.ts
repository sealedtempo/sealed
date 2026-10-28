import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadDefaults, parseDefaults, settlementDefaults, usdToUnits } from "../src/defaults.js";

const repoDefaults = join(import.meta.dirname, "../../../config/defaults.yaml");

describe("config/defaults.yaml loader", () => {
  it("loads the repo defaults", async () => {
    const d = await loadDefaults(repoDefaults, { testOverrides: false });
    expect(d.chain.chain_id).toBe(4217);
    expect(d.settlement_interval_minutes).toBe(60);
    expect(d.grace_period_minutes).toBe(1440);
    const s = settlementDefaults(d);
    expect(s.spendLimitPerDay).toBe(2_000_000n);
    expect(s.perPaymentCap).toBe(5_000_000n);
    expect(s.perDeploymentDailyCap).toBe(20_000_000n);
  });
  it("applies test_overrides on request", () => {
    const d = parseDefaults(readFileSync(repoDefaults, "utf8"), { testOverrides: true });
    expect(d.settlement_interval_minutes).toBe(5);
    expect(d.grace_period_minutes).toBe(5);
    expect(d.fees_usd.app_hour.crm).toBe(0.05);
  });
  it("honours SEALED_TEST_OVERRIDES=1", () => {
    process.env.SEALED_TEST_OVERRIDES = "1";
    try {
      expect(parseDefaults(readFileSync(repoDefaults, "utf8")).grace_period_minutes).toBe(5);
    } finally {
      delete process.env.SEALED_TEST_OVERRIDES;
    }
  });
  it("deep-merges nested overrides and validates", () => {
    const text = readFileSync(repoDefaults, "utf8").replace(
      "test_overrides: {grace_period_minutes: 5, settlement_interval_minutes: 5}",
      "test_overrides: {fees_usd: {app_hour: {crm: 1}}}",
    );
    const d = parseDefaults(text, { testOverrides: true });
    expect(d.fees_usd.app_hour.crm).toBe(1);
    expect(d.fees_usd.app_hour["coding-agent"]).toBe(0.05);
    expect(() => parseDefaults("codename: x\n", { testOverrides: false })).toThrow("defaults.yaml");
  });
});

describe("usdToUnits", () => {
  it("converts exactly with 6 decimals", () => {
    expect(usdToUnits(0.2, 6)).toBe(200_000n);
    expect(usdToUnits(0.05, 6)).toBe(50_000n);
    expect(usdToUnits(5, 6)).toBe(5_000_000n);
    expect(usdToUnits("0.000001", 6)).toBe(1n);
    // 0.1 + 0.2 is 0.30000000000000004 in binary floating point: refuse rather than round.
    expect(() => usdToUnits(0.1 + 0.2, 6)).toThrow("decimals");
  });
  it("rejects too many decimals and negatives", () => {
    expect(() => usdToUnits("0.0000001", 6)).toThrow("decimals");
    expect(() => usdToUnits(1e-7, 6)).toThrow("decimals");
    expect(() => usdToUnits(-1, 6)).toThrow();
  });
});
