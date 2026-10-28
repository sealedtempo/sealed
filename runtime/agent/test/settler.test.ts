import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveEnclavePrivateKey, feeScheduleFromDefaults, parseDefaults, usageDomain } from "@sealed/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isPaymentNeededConfig, PaymentGate, SocketCaddyAdmin } from "../src/caddy.js";
import type { PlatformClient } from "../src/evidence.js";
import { parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { emptyLedgerState, Ledger } from "../src/metering/ledger.js";
import { Settler } from "../src/payments/settler.js";
import type { PaymentStatus } from "../src/state.js";
import { type FakeCaddy, sampleCaddyConfig, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";

const defaults = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"), { testOverrides: true });
const GRACE = defaults.grace_period_minutes * 60;

describe("settlement, grace period and the payment-needed switch", () => {
  let dir: string;
  let caddy: FakeCaddy;
  let payer: FakePayer;
  let ledger: Ledger;
  let status: PaymentStatus;
  let settler: Settler;
  let usage: unknown[];
  let saved: unknown;
  let platformDown = false;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "settler-"));
    caddy = await startFakeCaddy(join(dir, "admin.sock"), sampleCaddyConfig("34-1-2-3"));
    payer = new FakePayer();
    usage = [];
    ledger = new Ledger(emptyLedgerState(1000), {
      deploymentId: `0x${"de".repeat(32)}`,
      apps: ["crm", "llm-gateway"],
      schedule: feeScheduleFromDefaults(defaults),
      domain: usageDomain(`0x${"04".repeat(20)}`, 4217),
      enclaveKey: deriveEnclavePrivateKey(`0x${"01".repeat(32)}`),
      perPaymentCap: () => payer.cap,
    });
    status = { failingSince: null, paymentNeeded: false };
    const platform: PlatformClient = {
      postEvidence: async () => ({ deploymentId: "0x" }),
      postUsage: async (b) => {
        if (platformDown) throw new Error("platform down");
        usage.push(b);
      },
      postHealth: async () => undefined,
    };
    const gate = new PaymentGate(new SocketCaddyAdmin(parseEndpoint(join(dir, "admin.sock"))), ["crm.34-1-2-3.sslip.io", "gateway.34-1-2-3.sslip.io"], {
      getOriginal: () => saved,
      setOriginal: async (c) => {
        saved = c;
      },
    });
    settler = new Settler({ ledger, payer, platform, gate, status, graceSec: GRACE, save: async () => {}, log: silentLogger });
  });
  afterEach(async () => {
    await caddy.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("uses the test_overrides grace period of 5 minutes", () => {
    expect(GRACE).toBe(300);
  });

  it("nothing due is not a failure", async () => {
    const r = await settler.tick(2000);
    expect(r.outcome).toBe("nothing_due");
    expect(r.reportCut).toBe(false);
  });

  it("pays every unpaid report of an app in one batch", async () => {
    payer.cap = 100_000n;
    await ledger.record("llm-gateway", "tokens", 1_200_000n, 1001); // 240_000 -> 100k + 100k + 40k
    const r = await settler.tick(2000);
    expect(r.outcome).toBe("settled");
    expect(payer.paid.length).toBe(1);
    expect(payer.paid[0]?.map((l) => l.amount)).toEqual([100_000n, 100_000n, 40_000n]);
    expect(new Set(payer.paid[0]?.map((l) => l.usageHash)).size).toBe(3);
    expect(usage.length).toBe(3);
    expect(ledger.unpaid()).toEqual([]);
  });

  it("defers what exceeds the FeeSplitter daily cap without counting it as a failure", async () => {
    payer.daily = 30_000n;
    payer.cap = 25_000n;
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000 -> 25k + 25k
    const r1 = await settler.tick(5000);
    expect(r1.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 25_000n })]);
    const r2 = await settler.tick(6000);
    expect(r2.apps).toEqual([{ app: "crm", result: "deferred", reason: "daily_cap" }]);
    expect(status.failingSince).toBeNull();
    payer.daily = 20_000_000n;
    expect((await settler.tick(7000)).apps[0]).toMatchObject({ result: "paid", amount: 25_000n });
  });

  it("switches app routes to the payment-needed page after the grace period and restores them after payment", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    const t0 = 10_000;
    const r1 = await settler.tick(t0);
    expect(r1.apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(status.failingSince).toBe(t0);
    expect(isPaymentNeededConfig(caddy.config)).toBe(false);
    await settler.tick(t0 + GRACE - 1);
    expect(isPaymentNeededConfig(caddy.config)).toBe(false);
    payer.budgetResult = { spendable: 1_000_000_000n };
    payer.failNext = 1;
    const r3 = await settler.tick(t0 + GRACE);
    expect(r3.apps[0]).toMatchObject({ result: "failed", reason: "tx_failed" });
    expect(r3.paymentNeeded).toBe(true);
    expect(isPaymentNeededConfig(caddy.config)).toBe(true);
    // Caddy restarted from its Caddyfile while still unpaid: the switch is re-applied.
    caddy.config = sampleCaddyConfig("34-1-2-3");
    payer.failNext = 1;
    await settler.tick(t0 + GRACE + 60);
    expect(isPaymentNeededConfig(caddy.config)).toBe(true);
    const r5 = await settler.tick(t0 + GRACE + 120);
    expect(r5.apps[0]).toMatchObject({ result: "paid" });
    expect(r5.paymentNeeded).toBe(false);
    expect(status.failingSince).toBeNull();
    expect(caddy.config).toEqual(sampleCaddyConfig("34-1-2-3"));
  });

  it("does not pay before the deployment is registered, and skips reports already paid onchain", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.active = false;
    expect((await settler.tick(2000)).outcome).toBe("deployment_not_active");
    expect(status.failingSince).toBeNull();
    payer.active = true;
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, entry!.fee);
    const r = await settler.tick(3000);
    expect(r.apps).toEqual([]);
    expect(ledger.unpaid()).toEqual([]);
  });

  // Verification finding on the contract review (logic-F1 b / funds-F-02): FeeSplitter cannot see the
  // report, so the deployment's own customer can open a leg first with 1 base unit. Before the fix the
  // settler took any non-zero usagePaid as paid and the real fee was never collected.
  it("a leg the customer paid short is not settled: the agent tops it up to the report's fee", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    const fee = entry!.fee;
    expect(fee).toBe(50_000n);
    payer.payDirectly(entry!.usageHash, entry!.appId, 1n);
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: fee - 1n, reports: 1 })]);
    expect(payer.paid).toEqual([[{ appId: entry!.appId, usageHash: entry!.usageHash, amount: fee - 1n, paid: 1n }]]);
    expect(await payer.paidAmount(entry!.usageHash, entry!.appId)).toBe(fee);
    expect(ledger.unpaid()).toEqual([]);
  });

  it("a leg paid at or above its fee onchain is settled without paying again", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.record("llm-gateway", "tokens", 1_000_000n, 1002);
    await ledger.closePeriod(1500);
    const [crm, llm] = ledger.unpaid();
    payer.payDirectly(crm!.usageHash, crm!.appId, crm!.fee);
    payer.payDirectly(llm!.usageHash, llm!.appId, llm!.fee + 1n);
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([]);
    expect(payer.paid).toEqual([]);
    expect(ledger.unpaid()).toEqual([]);
  });

  it("1-unit payments after a withheld tick keep failing until the shortfall is paid, then switch to payment-needed", async () => {
    // The exploit: the customer makes one settlement fail by withholding funds, pays 1 base unit for
    // every leg itself, and expects the next tick to see usagePaid > 0 and clear failingSince.
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.record("llm-gateway", "tokens", 1_000_000n, 1001);
    await ledger.closePeriod(1500);
    const legs = ledger.unpaid();
    expect(legs.length).toBe(2);
    payer.budgetResult = { spendable: 0n, problem: "insufficient_balance" };
    const t0 = 10_000;
    expect((await settler.tick(t0)).outcome).toBe("failed");
    for (const l of legs) payer.payDirectly(l.usageHash, l.appId, 1n);
    const r2 = await settler.tick(t0 + 60);
    expect(r2.outcome).toBe("failed");
    expect(r2.apps.map((a) => a.result)).toEqual(["failed", "failed"]);
    expect(status.failingSince).toBe(t0);
    expect(ledger.unpaid().length).toBe(2);
    const r3 = await settler.tick(t0 + GRACE);
    expect(r3.paymentNeeded).toBe(true);
    expect(isPaymentNeededConfig(caddy.config)).toBe(true);
    // Funds back: the agent pulls each leg's shortfall and the routes come back.
    payer.budgetResult = { spendable: 1_000_000_000n };
    const r4 = await settler.tick(t0 + GRACE + 60);
    expect(r4.outcome).toBe("settled");
    expect(r4.apps.map((a) => a.result === "paid" && a.amount)).toEqual(legs.map((l) => l.fee - 1n));
    for (const l of legs) expect(await payer.paidAmount(l.usageHash, l.appId)).toBe(l.fee);
    expect(r4.paymentNeeded).toBe(false);
    expect(status.failingSince).toBeNull();
    expect(caddy.config).toEqual(sampleCaddyConfig("34-1-2-3"));
  });

  it("budgets and the daily cap count only the shortfall of a short leg", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, 40_000n);
    payer.daily = 10_000n;
    payer.budgetResult = { spendable: 10_000n };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 10_000n })]);
    expect(payer.daily).toBe(0n);
  });

  it("a top-up that races the customer's own top-up to the fee fails one tick; the next sees the leg settled", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, 1n);
    // The customer completes the leg between the agent's read and its transaction: topUpFees reverts
    // NothingToTopUp instead of paying twice.
    const read = payer.paidAmount.bind(payer);
    let raced = false;
    payer.paidAmount = async (h, a) => {
      const v = await read(h, a);
      if (!raced) {
        raced = true;
        payer.payDirectly(h, a, entry!.fee - 1n);
      }
      return v;
    };
    const r1 = await settler.tick(2000);
    expect(r1.apps).toEqual([{ app: "crm", result: "failed", reason: "tx_failed" }]);
    const r2 = await settler.tick(2060);
    expect(r2.apps).toEqual([]);
    expect(ledger.unpaid()).toEqual([]);
    expect(status.failingSince).toBeNull();
  });

  it("keeps reports for later submission when the platform is down", async () => {
    platformDown = true;
    await ledger.record("crm", "app_hour", 60n, 1001);
    expect((await settler.tick(2000)).submitted).toBe(0);
    platformDown = false;
    expect((await settler.tick(3000)).submitted).toBe(1);
  });
});
