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
    payer.paid.push([{ appId: entry!.appId, amount: entry!.fee, usageHash: entry!.usageHash }]);
    const r = await settler.tick(3000);
    expect(r.apps).toEqual([]);
    expect(ledger.unpaid()).toEqual([]);
  });

  it("keeps reports for later submission when the platform is down", async () => {
    platformDown = true;
    await ledger.record("crm", "app_hour", 60n, 1001);
    expect((await settler.tick(2000)).submitted).toBe(0);
    platformDown = false;
    expect((await settler.tick(3000)).submitted).toBe(1);
  });
});
