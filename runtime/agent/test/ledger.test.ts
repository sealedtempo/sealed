import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  appId,
  deriveEnclavePrivateKey,
  enclaveSignerAddress,
  feeScheduleFromDefaults,
  parseDefaults,
  recoverUsageReportSigner,
  usageDomain,
  usageReportDigest,
  usageReportFromJson,
} from "@sealed/core";
import { describe, expect, it } from "vitest";
import { emptyLedgerState, Ledger, LedgerUnverifiedError, MAX_CUTS_PER_EVENT, TooManyReportsError, type VerifiedReport } from "../src/metering/ledger.js";
import { USAGE_LIMITS, UsageLimiter, UsageLimitError } from "../src/metering/limits.js";

const defaults = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"), { testOverrides: false });
const schedule = feeScheduleFromDefaults(defaults);
const seed = `0x${"77".repeat(32)}` as const;
const key = deriveEnclavePrivateKey(seed);
const domain = usageDomain("0x0000000000000000000000000000000000000fee", 4217);
const deploymentId = `0x${"de".repeat(32)}` as const;

function ledger(cap = 5_000_000n, start = 1000) {
  return new Ledger(emptyLedgerState(start), { deploymentId, apps: ["crm", "llm-gateway", "scraper"], schedule, domain, enclaveKey: key, perPaymentCap: () => cap });
}

describe("usage ledger", () => {
  it("aggregates per app and unit, prices on close and signs an EIP-712 report", async () => {
    const l = ledger();
    await l.record("llm-gateway", "tokens", 600_000n, 1001);
    await l.record("llm-gateway", "tokens", 650_000n, 1002);
    await l.record("crm", "app_hour", 3600n, 1003);
    await l.record("scraper", "pages", 3n, 1004);
    const r = await l.closePeriod(4600);
    expect(r).toBeDefined();
    const report = usageReportFromJson(r!.report);
    expect(report.periodStart).toBe(1000n);
    expect(report.periodEnd).toBe(4600n);
    expect(report.items).toEqual([
      { appId: appId("crm"), unit: 3, quantity: 3600n, fee: 50_000n },
      { appId: appId("llm-gateway"), unit: 1, quantity: 1_250_000n, fee: 250_000n },
      { appId: appId("scraper"), unit: 2, quantity: 3n, fee: 600n },
    ]);
    expect(r!.usageHash).toBe(usageReportDigest(report, domain));
    expect((await recoverUsageReportSigner(report, domain, r!.signature)).toLowerCase()).toBe(enclaveSignerAddress(seed));
    expect(l.unpaid().map((u) => [u.app, u.fee])).toEqual([["crm", 50_000n], ["llm-gateway", 250_000n], ["scraper", 600n]]);
    expect(l.state.periodStart).toBe(4600);
    expect(await l.closePeriod(5000)).toBeUndefined();
  });

  it("carries pricing remainders into the next period", async () => {
    const l = ledger();
    await l.record("llm-gateway", "tokens", 7n, 1001);
    const r1 = await l.closePeriod(1100);
    expect(r1!.report.items[0]?.fee).toBe("1");
    expect(l.state.carry["llm-gateway:tokens"]).toBe("400000");
    expect(r1!.payments["llm-gateway"]?.fee).toBe("1");
    await l.record("llm-gateway", "tokens", 3n, 1101);
    const r2 = await l.closePeriod(1200);
    expect(r2!.report.items[0]?.fee).toBe("1");
    expect(l.state.carry["llm-gateway:tokens"]).toBe("0");
  });

  it("cuts the period so no app fee exceeds the per-payment cap", async () => {
    const l = ledger(1_000_000n);
    const cut = await l.record("llm-gateway", "tokens", 12_000_000n, 2000);
    expect(cut.length).toBe(2);
    const last = await l.closePeriod(2100);
    const fees = [...cut, last!].map((r) => BigInt(r.payments["llm-gateway"]!.fee));
    expect(fees).toEqual([1_000_000n, 1_000_000n, 400_000n]);
    const quantities = [...cut, last!].map((r) => BigInt(r.report.items[0]!.quantity));
    expect(quantities.reduce((a, b) => a + b, 0n)).toBe(12_000_000n);
    const hashes = new Set([...cut, last!].map((r) => r.usageHash));
    expect(hashes.size).toBe(3);
    const starts = [...cut, last!].map((r) => r.report.periodStart);
    expect(starts).toEqual([1000, 2000, 2001]);
  });

  it("the cap counts every unit of the app together", async () => {
    const l = ledger(300_000n);
    await l.record("llm-gateway", "tokens", 1_000_000n, 1001); // 200_000
    const cut = await l.record("llm-gateway", "pages", 1000n, 1002); // would add 200_000
    expect(cut.length).toBe(1);
    expect(BigInt(cut[0]!.payments["llm-gateway"]!.fee)).toBeLessThanOrEqual(300_000n);
  });

  it("dedupes idempotency keys, rejects unknown apps, tracks payments and totals", async () => {
    const l = ledger();
    expect(l.seen("a")).toBe(false);
    expect(l.seen("a")).toBe(true);
    await expect(l.record("ghost", "tokens", 1n, 1001)).rejects.toThrow("unknown app");
    await l.record("crm", "app_hour", 7200n, 1001);
    const r = await l.closePeriod(9000);
    expect(l.totals()).toEqual({ metered: 100_000n, unpaid: 100_000n });
    l.markPaid(r!.usageHash, "crm", `0x${"11".repeat(32)}`, 9001);
    expect(l.unpaid()).toEqual([]);
    expect(l.totals()).toEqual({ metered: 100_000n, unpaid: 0n });
    expect(l.unsubmitted().length).toBe(1);
    l.markSubmitted(r!.usageHash);
    expect(l.unsubmitted().length).toBe(0);
  });

  it("free usage still produces an item but no payment", async () => {
    const l = ledger();
    await l.record("llm-gateway", "app_hour", 60n, 1001);
    const r = await l.closePeriod(1100);
    expect(r!.report.items).toEqual([{ appId: appId("llm-gateway"), unit: 3, quantity: "60", fee: "0" }]);
    expect(r!.payments).toEqual({});
  });

  // Review finding: one event of 5e10 tokens cut and signed about 2000 reports in one call.
  it("refuses an event that would cut more than a few reports, and records nothing of it", async () => {
    const l = ledger(1_000_000n);
    await l.record("llm-gateway", "tokens", 1000n, 1001);
    const before = structuredClone(l.state);
    const tooMuch = 5_000_000n * BigInt(MAX_CUTS_PER_EVENT + 1); // fee = 1 USD x (MAX + 1)
    await expect(l.record("llm-gateway", "tokens", tooMuch, 1002)).rejects.toThrow(TooManyReportsError);
    expect(l.state).toEqual(before);
    const fits = await l.record("llm-gateway", "tokens", 5_000_000n * BigInt(MAX_CUTS_PER_EVENT), 1003);
    expect(fits.length).toBeLessThanOrEqual(MAX_CUTS_PER_EVENT + 1);
  });

  // Review finding: closePeriod cleared the open period after awaiting the signature, which would
  // drop usage recorded meanwhile once signing is asynchronous.
  it("usage recorded while a period is being closed lands in the next period", async () => {
    const l = ledger();
    await l.record("llm-gateway", "tokens", 1_000_000n, 1001);
    const closing = l.closePeriod(2000);
    const late = l.record("llm-gateway", "tokens", 5n, 2000);
    const r = await closing;
    await late;
    expect(r!.report.items[0]?.quantity).toBe("1000000");
    expect(l.state.open["llm-gateway"]?.tokens).toBe("5");
    expect(l.state.periodStart).toBe(2000);
  });
});

describe("usage limits", () => {
  it("caps each event and each app and unit per clock hour", () => {
    const lim = new UsageLimiter();
    expect(() => lim.admit("llm-gateway", "tokens", USAGE_LIMITS.tokens.perEvent + 1n, 0)).toThrow(UsageLimitError);
    lim.admit("crm", "app_hour", 3600n, 7200);
    lim.admit("crm", "app_hour", 3600n, 7300);
    try {
      lim.admit("crm", "app_hour", 1n, 7400);
      expect.unreachable();
    } catch (err) {
      expect((err as UsageLimitError).status).toBe(429);
    }
    lim.admit("crm", "app_hour", 1n, 10_800); // the next hour starts fresh
    lim.admit("other", "app_hour", 3600n, 7400); // per app
    lim.admit("crm", "app_hour", 3600n, 10_801);
    expect(() => lim.admit("crm", "app_hour", 3600n, 10_802)).toThrow(UsageLimitError);
    lim.release("crm", "app_hour", 1n, 10_802);
    lim.admit("crm", "app_hour", 3600n, 10_803);
  });
});

describe("ledger rebuild after a disk rollback (D-062)", () => {
  const verified = (r: { report: ReturnType<typeof usageReportFromJson>; signature: `0x${string}` }): VerifiedReport => ({
    report: r.report,
    signature: r.signature,
    usageHash: usageReportDigest(r.report, domain),
    receivedAt: Number(r.report.periodEnd),
  });

  it("holds the usage read from disk and cuts nothing until the stored reports are merged", async () => {
    const l = ledger(100_000n);
    await l.record("llm-gateway", "tokens", 100_000n, 1001); // 20_000
    l.holdForRebuild(1050);
    expect(l.verified).toBe(false);
    expect(l.state.open).toEqual({});
    expect(l.state.held).toEqual([{ periodStart: 1000, open: { "llm-gateway": { tokens: "100000" } } }]);
    expect(l.state.periodStart).toBe(1050); // usage from the boot on starts its own period
    // New usage waits in the open period; usage that would need a cut is refused untouched.
    await l.record("llm-gateway", "tokens", 50_000n, 1100);
    await expect(l.record("llm-gateway", "tokens", 1_000_000n, 1101)).rejects.toThrow(LedgerUnverifiedError);
    expect(l.state.open).toEqual({ "llm-gateway": { tokens: "50000" } });
    await expect(l.closePeriod(1200)).rejects.toThrow(LedgerUnverifiedError);
    // Nothing was signed for this deployment: the held usage comes back.
    const r = l.adopt([]);
    expect(r).toMatchObject({ adopted: 0, droppedUsage: 0, keptUsage: 1 });
    expect(l.state.open).toEqual({ "llm-gateway": { tokens: "150000" } });
    expect(l.state.periodStart).toBe(1000);
    expect((await l.closePeriod(1300))?.report.periodStart).toBe(1000);
  });

  it("drops held usage a signed report already covers, adopts the reports it did not know, and never signs an overlapping period", async () => {
    // The VM that ran on after the host took its copy: it cut R1 (with the held usage) and R2.
    const ran = ledger();
    await ran.record("llm-gateway", "tokens", 100_000n, 1001);
    const copy = JSON.parse(JSON.stringify(ran.state));
    const r1 = (await ran.closePeriod(4600)) as NonNullable<Awaited<ReturnType<Ledger["closePeriod"]>>>;
    await ran.record("crm", "app_hour", 3600n, 4700);
    const r2 = (await ran.closePeriod(8200)) as NonNullable<Awaited<ReturnType<Ledger["closePeriod"]>>>;
    // The rolled-back copy boots: it holds the 100k tokens R1 already billed.
    const l = new Ledger(copy, { deploymentId, apps: ["crm", "llm-gateway", "scraper"], schedule, domain, enclaveKey: key, perPaymentCap: () => 5_000_000n });
    l.holdForRebuild();
    await l.record("scraper", "pages", 2n, 9000); // after the boot
    const fromPlatform = [r1, r2].map((r) => verified({ report: usageReportFromJson(r.report), signature: r.signature }));
    const res = l.adopt(fromPlatform, `4600:${r2.usageHash}`);
    expect(res).toMatchObject({ adopted: 2, droppedUsage: 1, keptUsage: 0, signedThrough: 8200 });
    expect(l.state.platformCursor).toBe(`4600:${r2.usageHash}`);
    expect(l.state.open).toEqual({ scraper: { pages: "2" } });
    expect(l.state.periodStart).toBe(8200);
    // Adopted legs are submitted and unpaid until the settler sees usagePaid onchain.
    expect(l.unpaid().map((u) => [u.app, u.fee, u.submitted])).toEqual([["llm-gateway", 20_000n, true], ["crm", 50_000n, true]]);
    const next = await l.closePeriod(9100);
    expect(next?.report.periodStart).toBe(8200);
    // Adopting the same reports again changes nothing.
    expect(l.adopt(fromPlatform)).toMatchObject({ adopted: 0, droppedUsage: 0 });
    expect(l.state.reports).toHaveLength(3);
  });

  it("usage recorded after a boot is kept even when a later rebuild drops the usage held from disk", async () => {
    const ran = ledger();
    await ran.record("llm-gateway", "tokens", 100_000n, 1001);
    const copy = JSON.parse(JSON.stringify(ran.state));
    const r1 = (await ran.closePeriod(4600)) as NonNullable<Awaited<ReturnType<Ledger["closePeriod"]>>>;
    // Boot 1 on the rolled-back copy cannot read the platform; it records new usage and stops.
    const boot1 = new Ledger(copy, { deploymentId, apps: ["crm", "llm-gateway", "scraper"], schedule, domain, enclaveKey: key, perPaymentCap: () => 5_000_000n });
    boot1.holdForRebuild(5000);
    await boot1.record("crm", "app_hour", 60n, 5010);
    // Boot 2 on that state reads the platform.
    const boot2 = new Ledger(JSON.parse(JSON.stringify(boot1.state)), { deploymentId, apps: ["crm", "llm-gateway", "scraper"], schedule, domain, enclaveKey: key, perPaymentCap: () => 5_000_000n });
    boot2.holdForRebuild(6000);
    expect(boot2.state.held?.map((h) => h.periodStart)).toEqual([1000, 5000]);
    const res = boot2.adopt([verified({ report: usageReportFromJson(r1.report), signature: r1.signature })]);
    expect(res).toMatchObject({ droppedUsage: 1, keptUsage: 1, signedThrough: 4600 });
    expect(boot2.state.open).toEqual({ crm: { app_hour: "60" } });
    expect(boot2.state.periodStart).toBe(5000);
  });

  it("keeps held usage from a period no signed report reaches, and marks its own reports the platform holds as submitted", async () => {
    const l = ledger();
    await l.record("crm", "app_hour", 60n, 1001);
    const mine = (await l.closePeriod(2000)) as NonNullable<Awaited<ReturnType<Ledger["closePeriod"]>>>;
    expect(mine.submitted).toBe(false);
    await l.record("crm", "app_hour", 30n, 2100);
    l.holdForRebuild();
    const res = l.adopt([verified({ report: usageReportFromJson(mine.report), signature: mine.signature })]);
    expect(res).toMatchObject({ adopted: 0, confirmed: 1, keptUsage: 1, droppedUsage: 0, signedThrough: 2000 });
    expect(l.state.reports[0]?.submitted).toBe(true);
    expect(l.state.open).toEqual({ crm: { app_hour: "30" } });
    expect(l.state.periodStart).toBe(2000);
  });

  it("ignores stored reports of another deployment and items of apps it does not know", async () => {
    const l = ledger();
    l.holdForRebuild();
    const other = { deploymentId: `0x${"ab".repeat(32)}` as const, periodStart: 0n, periodEnd: 99_999n, items: [] };
    const res = l.adopt([{ report: other, signature: "0x", usageHash: `0x${"11".repeat(32)}`, receivedAt: 1 }]);
    expect(res).toMatchObject({ adopted: 0, signedThrough: 0 });
  });

  it("a void report is never unpaid, submitted again or counted", async () => {
    const l = ledger();
    await l.record("crm", "app_hour", 3600n, 1001);
    const r = (await l.closePeriod(2000)) as NonNullable<Awaited<ReturnType<Ledger["closePeriod"]>>>;
    l.voidReport(r.usageHash);
    expect(l.unpaid()).toEqual([]);
    expect(l.unsubmitted()).toEqual([]);
    expect(l.totals()).toEqual({ metered: 0n, unpaid: 0n });
    // Its period still counts as signed.
    expect(l.state.signedThrough).toBe(2000);
  });
});

