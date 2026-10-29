import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveEnclavePrivateKey, feeScheduleFromDefaults, parseDefaults, usageDomain } from "@sealed/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DirectCaddySwitch } from "../src/caddy.js";
import type { PlatformClient } from "../src/evidence.js";
import { HttpError, parseEndpoint } from "../src/http.js";
import { silentLogger } from "../src/log.js";
import { emptyLedgerState, Ledger } from "../src/metering/ledger.js";
import { emptyBudgetState, SpendBudget } from "../src/payments/budget.js";
import type { Budget, PaymentLine } from "../src/payments/feePayer.js";
import { PENDING_GIVE_UP_SEC, PLATFORM_SIDE_FAILURES, Settler } from "../src/payments/settler.js";
import type { PaymentStatus } from "../src/state.js";
import { type FakeCaddy, startFakeCaddy } from "./helpers/fakeCaddy.js";
import { FakePayer } from "./helpers/fakePayer.js";
import { CADDYFILE, CADDYFILE_PAYMENT_NEEDED } from "./helpers/fixtures.js";

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
  let platformDown = false;
  let capSeen: bigint[];
  const paymentNeededShown = () => caddy.current === CADDYFILE_PAYMENT_NEEDED;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "settler-"));
    caddy = await startFakeCaddy(join(dir, "admin.sock"), CADDYFILE);
    payer = new FakePayer();
    usage = [];
    capSeen = [];
    platformDown = false;
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
    const gate = new DirectCaddySwitch(parseEndpoint(join(dir, "admin.sock")), { normal: CADDYFILE, paymentNeeded: CADDYFILE_PAYMENT_NEEDED });
    settler = new Settler({ ledger, payer, platform, gate, status, graceSec: GRACE, save: async () => {}, log: silentLogger, onPerPaymentCap: (c) => capSeen.push(c) });
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
    expect(status.failingSince).toBeNull();
  });

  it("pays every unpaid report of an app in one batch and hands the onchain cap to the ledger", async () => {
    payer.cap = 100_000n;
    await ledger.record("llm-gateway", "tokens", 1_200_000n, 1001); // 240_000 -> 100k + 100k + 40k
    const r = await settler.tick(2000);
    expect(r.outcome).toBe("settled");
    expect(payer.paid.length).toBe(1);
    expect(payer.paid[0]?.map((l) => l.amount)).toEqual([100_000n, 100_000n, 40_000n]);
    expect(new Set(payer.paid[0]?.map((l) => l.usageHash)).size).toBe(3);
    expect(usage.length).toBe(3);
    expect(ledger.unpaid()).toEqual([]);
    expect(capSeen).toEqual([100_000n]);
    // The network fee was estimated for exactly the batch that was sent.
    expect(payer.estimates.at(-1)).toEqual(payer.paid[0]);
  });

  it("defers what exceeds the FeeSplitter daily cap without counting it as a failure", async () => {
    payer.daily = 30_000n;
    payer.cap = 25_000n;
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000 -> 25k + 25k
    const r1 = await settler.tick(5000);
    expect(r1.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 25_000n }), { app: "crm", result: "deferred", reason: "daily_cap" }]);
    expect(r1.outcome).toBe("settled");
    const r2 = await settler.tick(6000);
    expect(r2.apps).toEqual([{ app: "crm", result: "deferred", reason: "daily_cap" }]);
    expect(status.failingSince).toBeNull();
    payer.daily = 20_000_000n;
    expect((await settler.tick(7000)).apps[0]).toMatchObject({ result: "paid", amount: 25_000n });
  });

  it("switches to the measured payment-needed Caddyfile after the grace period and back after payment", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    const t0 = 10_000;
    const r1 = await settler.tick(t0);
    expect(r1.apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(status.failingSince).toBe(t0);
    expect(paymentNeededShown()).toBe(false);
    await settler.tick(t0 + GRACE - 1);
    expect(paymentNeededShown()).toBe(false);
    payer.budgetResult = { spendable: 1_000_000_000n };
    payer.failNext = 1;
    const r3 = await settler.tick(t0 + GRACE);
    expect(r3.apps[0]).toMatchObject({ result: "failed", reason: "tx_failed" });
    expect(r3.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
    expect(caddy.contentTypes.every((t) => t === "text/caddyfile")).toBe(true);
    // Caddy restarted from its normal Caddyfile while still unpaid: the switch is re-applied.
    caddy.current = CADDYFILE;
    payer.failNext = 1;
    await settler.tick(t0 + GRACE + 60);
    expect(paymentNeededShown()).toBe(true);
    const r5 = await settler.tick(t0 + GRACE + 120);
    expect(r5.apps[0]).toMatchObject({ result: "paid" });
    expect(r5.paymentNeeded).toBe(false);
    expect(status.failingSince).toBeNull();
    expect(caddy.current).toBe(CADDYFILE);
  });

  it("keeps trying the switch when Caddy's admin API fails", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.budgetResult = { spendable: 0n, problem: "insufficient_balance" };
    await settler.tick(10_000);
    caddy.failNext = 1;
    expect((await settler.tick(10_000 + GRACE)).paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(false);
    await settler.tick(10_000 + GRACE + 60);
    expect(paymentNeededShown()).toBe(true);
  });

  // Review finding: an RPC error used to read as "deployment not active", which reset the failure clock.
  it("an RPC outage (a blocked firewall) counts as a failure and reaches the payment-needed page", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.rpcDown = true;
    const t0 = 10_000;
    for (let h = 0; h < 48; h++) {
      await ledger.record("crm", "app_hour", 3600n, t0 + h * 3600);
      const r = await settler.tick(t0 + h * 3600);
      expect(r.apps).toEqual([{ app: "*", result: "failed", reason: "rpc_error" }]);
    }
    expect(status.failingSince).toBe(t0);
    expect(status.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
    expect(status.lastOutcome).toBe("rpc_error");
    // RPC back: 48 legs, at most MAX_LINES_PER_TX per transaction. Paying the first ten is no recovery (payments-3):
    // the routes come back with the transaction that leaves nothing overdue.
    payer.rpcDown = false;
    const backlog = ledger.unpaid().length;
    expect(backlog).toBe(48);
    let t = t0 + 48 * 3600;
    const rounds: string[] = [];
    while (ledger.unpaid().length > 0 && rounds.length < 10) {
      const r = await settler.tick(t);
      rounds.push(`${r.outcome}:${r.paymentNeeded}`);
      t += 60;
    }
    expect(rounds).toEqual(["partial:true", "partial:true", "partial:true", "partial:true", "settled:false"]);
    expect(status.failingSince).toBeNull();
    expect(caddy.current).toBe(CADDYFILE);
  });

  it("an RPC error while paying (after the status read) is a failure too", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.paidAmount = async () => {
      throw new Error("fetch failed");
    };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "*", result: "failed", reason: "rpc_error" }]);
    expect(status.failingSince).toBe(2000);
  });

  // D-073: the platform registers the deployment (the oracle checks the agent's evidence, the ops key submits it), so
  // an api the agent cannot reach at boot keeps it unregistered. That used to put the customer on the payment-needed
  // page one grace period after the oldest unpaid report.
  it("a deployment the platform has not registered yet defers settlement without a grace clock (D-073)", async () => {
    payer.deployment = "none";
    await ledger.record("crm", "app_hour", 3600n, 1001);
    const r1 = await settler.tick(2000);
    expect(r1).toMatchObject({ outcome: "deployment_not_registered", paymentNeeded: false, apps: [{ app: "*", result: "failed", reason: "deployment_not_registered" }] });
    expect(status).toMatchObject({ failingSince: null, deferredSince: 2000, lastOutcome: "deployment_not_registered" });
    await ledger.record("crm", "app_hour", 60n, 2001);
    const r2 = await settler.tick(2000 + 10 * GRACE);
    expect(r2.paymentNeeded).toBe(false);
    expect(paymentNeededShown()).toBe(false);
    expect(status.failingSince).toBeNull();
    expect(payer.paid).toEqual([]);
    // Registered at last: the deferred backlog is paid.
    payer.deployment = "active";
    const r3 = await settler.tick(2000 + 10 * GRACE + 60);
    expect(r3.outcome).toBe("settled");
    expect(r3.paymentNeeded).toBe(false);
    expect(ledger.unpaid()).toEqual([]);
    expect(status.deferredSince).toBeUndefined();
  });

  it("a Closed deployment switches to payment-needed at once and stays there", async () => {
    payer.deployment = "closed";
    const r1 = await settler.tick(2000);
    expect(r1.outcome).toBe("deployment_closed");
    expect(r1.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
    await ledger.record("crm", "app_hour", 3600n, 2001);
    const r2 = await settler.tick(3000);
    expect(r2.outcome).toBe("deployment_closed");
    expect(payer.paid).toEqual([]);
    expect(r2.paymentNeeded).toBe(true);
  });

  it("skips reports already paid onchain without a transaction", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, entry!.fee);
    const r = await settler.tick(3000);
    expect(r.apps).toEqual([]);
    expect(ledger.unpaid()).toEqual([]);
  });

  it("an app the registry does not list for the deployment is a failure, not a silent deferral", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.inDeployment = false;
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "not_in_deployment" }]);
    expect(status.failingSince).toBe(2000);
  });

  // Review finding: one leg above the onchain cap (lowered by the owner, or cut before the cap was read)
  // used to be batched and revert every tick.
  it("legs above the onchain per-payment cap are skipped and flagged; the rest of the app still pays", async () => {
    await ledger.record("llm-gateway", "tokens", 5_000_000n, 1001); // 1_000_000
    await ledger.closePeriod(1500);
    await ledger.record("llm-gateway", "tokens", 1_000_000n, 1501); // 200_000
    payer.cap = 500_000n;
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([
      { app: "llm-gateway", result: "deferred", reason: "over_payment_cap" },
      expect.objectContaining({ app: "llm-gateway", result: "paid", amount: 200_000n, reports: 1 }),
    ]);
    expect(status.overCap).toBe(1);
    expect(status.failingSince).toBeNull();
    expect(payer.estimates.flat().every((l) => l.amount <= 500_000n)).toBe(true);
    payer.cap = 5_000_000n;
    const r2 = await settler.tick(3000);
    expect(r2.apps).toEqual([expect.objectContaining({ result: "paid", amount: 1_000_000n })]);
    expect(status.overCap).toBe(0);
  });

  it("a backlog above the daily cap pays the oldest legs that fit, estimated for exactly that subset", async () => {
    payer.cap = 100_000n;
    await ledger.record("llm-gateway", "tokens", 2_000_000n, 1001); // 400_000 -> 4 x 100k
    payer.daily = 250_000n;
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ result: "paid", amount: 200_000n, reports: 2 }), { app: "llm-gateway", result: "deferred", reason: "daily_cap" }]);
    expect(payer.estimates).toEqual([payer.paid[0]]);
    expect(ledger.unpaid().length).toBe(2);
  });

  it("shrinks a batch whose estimate reverts and pays the part that goes through", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    await ledger.record("crm", "app_hour", 3600n, 1501);
    await ledger.closePeriod(1600);
    const reserve = payer.feeReserve.bind(payer);
    payer.feeReserve = async (lines) => {
      if (lines.length > 1) throw new Error("execution reverted");
      return reserve(lines);
    };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ result: "paid", reports: 1 })]);
    expect(ledger.unpaid().length).toBe(1);
  });

  it("a single leg whose estimate reverts is a failure", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.feeReserve = async () => {
      throw new Error("execution reverted: Unauthorized()");
    };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "estimate_reverted" }]);
  });

  // payments-3: a budget that covered part of the due legs used to read as "paid", which ended the failure streak.
  it("a budget that covers only part of an app's legs is a failure: the streak runs on although something is paid", async () => {
    for (let i = 0; i < 3; i++) {
      await ledger.record("crm", "app_hour", 3600n, 1001 + i * 100);
      await ledger.closePeriod(1050 + i * 100);
    }
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    const t0 = 10_000;
    expect((await settler.tick(t0)).apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    // Enough for one 50_000 leg and its network fee, not for two.
    payer.budgetResult = { spendable: 60_000n, binding: "spend_limit" };
    const r1 = await settler.tick(t0 + 60);
    expect(r1.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 50_000n, reports: 1 }), { app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(r1.outcome).toBe("partial");
    expect(status.failingSince).toBe(t0);
    const r2 = await settler.tick(t0 + GRACE);
    expect(r2.apps).toEqual([expect.objectContaining({ result: "paid", reports: 1 }), { app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(r2.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
    payer.budgetResult = { spendable: 1_000_000_000n };
    const r3 = await settler.tick(t0 + GRACE + 60);
    expect(r3).toMatchObject({ outcome: "settled", paymentNeeded: false, apps: [expect.objectContaining({ result: "paid", reports: 1 })] });
    expect(ledger.unpaid()).toEqual([]);
    expect(caddy.current).toBe(CADDYFILE);
  });

  it("a network fee that pushes the last leg out of the budget is a shortfall too", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    await ledger.record("crm", "app_hour", 3600n, 1501);
    await ledger.closePeriod(1600);
    // Both legs fit without the network fee (2 x 1000 for two lines), one leg fits with it.
    payer.budgetResult = { spendable: 101_000n };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ result: "paid", reports: 1 }), { app: "crm", result: "failed", reason: "insufficient_balance" }]);
    expect(status.failingSince).toBe(2000);
  });

  // payments-3 step 4: one transaction pays at most MAX_LINES_PER_TX legs; the rest wait without a usagePaid read.
  describe("a backlog longer than one transaction", () => {
    async function backlog(n: number) {
      for (let i = 0; i < n; i++) {
        await ledger.record("crm", "app_hour", 3600n, 1001 + i * 100);
        await ledger.closePeriod(1050 + i * 100);
      }
    }

    it("keeps a customer-side streak and the payment-needed page until the whole backlog is paid", async () => {
      await backlog(25);
      payer.budgetResult = { spendable: 0n, problem: "insufficient_balance" };
      const t0 = 10_000;
      await settler.tick(t0);
      expect((await settler.tick(t0 + GRACE)).paymentNeeded).toBe(true);
      payer.budgetResult = { spendable: 1_000_000_000n };
      const reads = payer.paidReads;
      const r1 = await settler.tick(t0 + GRACE + 60);
      expect(payer.paidReads - reads).toBe(10);
      expect(r1).toMatchObject({ outcome: "partial", paymentNeeded: true, apps: [expect.objectContaining({ result: "paid", reports: 10 })] });
      expect(status.failingSince).toBe(t0);
      expect(paymentNeededShown()).toBe(true);
      expect((await settler.tick(t0 + GRACE + 120)).outcome).toBe("partial");
      const r3 = await settler.tick(t0 + GRACE + 180);
      expect(r3).toMatchObject({ outcome: "settled", paymentNeeded: false, apps: [expect.objectContaining({ result: "paid", reports: 5 })] });
      expect(status.failingSince).toBeNull();
      expect(caddy.current).toBe(CADDYFILE);
    });

    it("is no failure for a customer whose side works (a backlog left by a platform outage)", async () => {
      platformDown = true;
      await backlog(25);
      await settler.tick(9_000);
      platformDown = false;
      const outcomes: string[] = [];
      for (let t = 10_000; ledger.unpaid().length > 0 && outcomes.length < 5; t += 60) {
        const r = await settler.tick(t);
        outcomes.push(r.outcome);
        expect(status.failingSince).toBeNull();
        expect(r.paymentNeeded).toBe(false);
      }
      expect(outcomes).toEqual(["partial", "partial", "settled"]);
    });

    it("legs above the per-payment cap are still found behind a long backlog", async () => {
      await backlog(12);
      await ledger.record("llm-gateway", "tokens", 5_000_000n, 4000); // 1_000_000
      await ledger.closePeriod(4100);
      payer.cap = 500_000n;
      await settler.tick(5000);
      expect(Object.values(status.unpayable ?? {})).toEqual(["over_payment_cap"]);
      expect(status.overCap).toBe(1);
    });
  });

  // payments-4: FeeSplitter.pause() (owner only) makes payFees and topUpFees revert EnforcedPause. That is the operator's
  // side (D-073): it used to count as estimate_reverted, so a pause longer than the grace period put every customer on
  // the payment-needed page.
  describe("a paused FeeSplitter (the operator's side)", () => {
    it("defers settlement without a grace clock, and pays everything once unpaused", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.paused = true;
      const r1 = await settler.tick(2000);
      expect(r1).toMatchObject({ outcome: "failed", paymentNeeded: false, apps: [{ app: "crm", result: "failed", reason: "fee_splitter_paused" }] });
      expect(status).toMatchObject({ failingSince: null, deferredSince: 2000, lastOutcome: "fee_splitter_paused" });
      await ledger.record("crm", "app_hour", 3600n, 2001);
      expect((await settler.tick(2000 + 10 * GRACE)).paymentNeeded).toBe(false);
      expect(paymentNeededShown()).toBe(false);
      expect(payer.paid).toEqual([]);
      payer.paused = false;
      const r3 = await settler.tick(2000 + 10 * GRACE + 60);
      expect(r3).toMatchObject({ outcome: "settled", paymentNeeded: false, apps: [expect.objectContaining({ result: "paid", reports: 2 })] });
      expect(status.deferredSince).toBeUndefined();
      expect(ledger.unpaid()).toEqual([]);
    });

    it("pauses a running grace period and resumes it after the unpause", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
      const t0 = 10_000;
      await settler.tick(t0);
      // The customer fixes the limit 100 s in, but the operator has paused FeeSplitter for three grace periods.
      payer.budgetResult = { spendable: 1_000_000_000n };
      payer.paused = true;
      expect((await settler.tick(t0 + 100)).apps).toEqual([{ app: "crm", result: "failed", reason: "fee_splitter_paused" }]);
      await settler.tick(t0 + 100 + 3 * GRACE);
      expect(status).toMatchObject({ failingSince: t0, deferredSince: t0 + 100 });
      expect(paymentNeededShown()).toBe(false);
      payer.paused = false;
      const back = await settler.tick(t0 + 100 + 3 * GRACE + 10);
      expect(back).toMatchObject({ outcome: "settled", paymentNeeded: false });
      expect(status.failingSince).toBeNull();
      expect(status.deferredSince).toBeUndefined();
    });

    it("does not hide a customer-side failure: an exhausted limit during a pause runs the grace period", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.paused = true;
      payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
      const t0 = 10_000;
      expect((await settler.tick(t0)).apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
      expect(status.failingSince).toBe(t0);
      expect(status.deferredSince).toBeUndefined();
      expect((await settler.tick(t0 + GRACE)).paymentNeeded).toBe(true);
    });

    it("a budget that covers only part of the legs still counts while the batch reverts EnforcedPause", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      await ledger.closePeriod(1500);
      await ledger.record("crm", "app_hour", 3600n, 1501);
      await ledger.closePeriod(1600);
      payer.paused = true;
      payer.budgetResult = { spendable: 60_000n, binding: "spend_limit" };
      const r = await settler.tick(2000);
      expect(r.apps).toEqual([
        { app: "crm", result: "failed", reason: "spend_limit" },
        { app: "crm", result: "failed", reason: "fee_splitter_paused" },
      ]);
      expect(status.failingSince).toBe(2000);
    });

    it("a pause between the estimate and the transaction is the operator's side too", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      const reserve = payer.feeReserve.bind(payer);
      payer.feeReserve = async (lines) => {
        const v = await reserve(lines);
        payer.paused = true;
        return v;
      };
      const r = await settler.tick(2000);
      expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "fee_splitter_paused" }]);
      expect(status).toMatchObject({ failingSince: null, deferredSince: 2000 });
    });

    it("decodes EnforcedPause from the revert alone when paused() cannot be read", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.splitterPaused = async () => {
        throw new Error("fetch failed");
      };
      payer.feeReserve = async () => {
        throw new Error('The contract function "payFees" reverted. Error: EnforcedPause()');
      };
      expect((await settler.tick(2000)).apps).toEqual([{ app: "crm", result: "failed", reason: "fee_splitter_paused" }]);
      payer.feeReserve = async () => {
        throw new Error("execution reverted: Unauthorized()");
      };
      expect((await settler.tick(2100)).apps).toEqual([{ app: "crm", result: "failed", reason: "estimate_reverted" }]);
    });
  });

  it("the network fee must fit the budget on top of the fees", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000
    payer.budgetResult = { spendable: 50_500n };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "insufficient_balance" }]);
    payer.budgetResult = { spendable: 51_000n };
    expect((await settler.tick(2100)).apps[0]).toMatchObject({ result: "paid", amount: 50_000n });
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

  it("a leg the customer opened in another token cannot be topped up: a failure, the app's other legs still pay", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    await ledger.record("crm", "app_hour", 3600n, 1501);
    const [first] = ledger.unpaid();
    payer.payDirectly(first!.usageHash, first!.appId, 1n, "0x20c0000000000000000000000000000000000001");
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([
      { app: "crm", result: "failed", reason: "leg_token_mismatch" },
      expect.objectContaining({ app: "crm", result: "paid", amount: 50_000n, reports: 1 }),
    ]);
    expect(r.outcome).toBe("partial");
    expect(status.failingSince).toBe(2000);
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
    expect(paymentNeededShown()).toBe(true);
    // Funds back: the agent pulls each leg's shortfall and the routes come back.
    payer.budgetResult = { spendable: 1_000_000_000n };
    const r4 = await settler.tick(t0 + GRACE + 60);
    expect(r4.outcome).toBe("settled");
    expect(r4.apps.map((a) => a.result === "paid" && a.amount)).toEqual(legs.map((l) => l.fee - 1n));
    for (const l of legs) expect(await payer.paidAmount(l.usageHash, l.appId)).toBe(l.fee);
    expect(r4.paymentNeeded).toBe(false);
    expect(status.failingSince).toBeNull();
    expect(caddy.current).toBe(CADDYFILE);
  });

  it("budgets and the daily cap count only the shortfall of a short leg", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, 40_000n);
    payer.daily = 10_000n;
    payer.budgetResult = { spendable: 10_000n + payer.reserve };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 10_000n })]);
    expect(payer.daily).toBe(0n);
  });

  it("a top-up that races the customer's own top-up to the fee fails one tick; the next sees the leg settled", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    await ledger.closePeriod(1500);
    const [entry] = ledger.unpaid();
    payer.payDirectly(entry!.usageHash, entry!.appId, 1n);
    // The customer completes the leg between the agent's estimate and its transaction: topUpFees
    // reverts NothingToTopUp instead of paying twice.
    const reserve = payer.feeReserve.bind(payer);
    payer.feeReserve = async (lines) => {
      const v = await reserve(lines);
      payer.payDirectly(entry!.usageHash, entry!.appId, entry!.fee - 1n);
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

  // D-062: every paid period must be among the reports the platform stores, or a rolled-back disk could bill it again.
  // D-073: while the platform does not accept them, settlement is deferred and the grace period does not run.
  it("pays a report only once the platform accepted it; until then settlement is deferred without a grace clock", async () => {
    platformDown = true;
    await ledger.record("crm", "app_hour", 3600n, 1001);
    const r1 = await settler.tick(2000);
    expect(r1).toMatchObject({ outcome: "failed", submitted: 0, apps: [{ app: "*", result: "failed", reason: "usage_not_submitted" }] });
    expect(payer.paid).toEqual([]);
    expect(status.failingSince).toBeNull();
    expect(status.deferredSince).toBe(2000);
    expect(status.lastOutcome).toBe("usage_not_submitted");
    // An outage far longer than the grace period never shows the payment-needed page.
    const r2 = await settler.tick(2000 + 10 * GRACE);
    expect(r2.paymentNeeded).toBe(false);
    expect(paymentNeededShown()).toBe(false);
    expect(status.failingSince).toBeNull();
    platformDown = false;
    const r3 = await settler.tick(2100 + 10 * GRACE);
    expect(r3.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" })]);
    expect(status.failingSince).toBeNull();
    expect(status.deferredSince).toBeUndefined();
  });

  // D-073: a failure on the customer's side starts the grace clock; a platform outage pauses it, never resets it.
  it("pauses a running grace period while the platform is unreachable and resumes it after", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    const t0 = 10_000;
    await settler.tick(t0);
    expect(status.failingSince).toBe(t0);
    // 100 s into the grace period the VM reboots while the platform cannot be reached: the boot rebuild of the
    // ledger (D-062) fails, so nothing is cut or paid, for three grace periods.
    ledger.holdForRebuild();
    let readable = false;
    const gate = new DirectCaddySwitch(parseEndpoint(join(dir, "admin.sock")), { normal: CADDYFILE, paymentNeeded: CADDYFILE_PAYMENT_NEEDED });
    settler = new Settler({
      ledger,
      payer,
      gate,
      platform: { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async (b) => usage.push(b), postHealth: async () => undefined },
      status,
      graceSec: GRACE,
      save: async () => {},
      log: silentLogger,
      rebuild: async () => {
        if (readable) ledger.adopt([]);
        return readable;
      },
    });
    const blind = await settler.tick(t0 + 100);
    expect(blind.apps).toEqual([{ app: "*", result: "failed", reason: "ledger_unverified" }]);
    await settler.tick(t0 + 100 + 3 * GRACE);
    expect(status.deferredSince).toBe(t0 + 100);
    expect(status.failingSince).toBe(t0);
    expect(paymentNeededShown()).toBe(false);
    // Back, and the customer's limit is still exhausted: the outage does not count, 100 s of the grace period were used.
    readable = true;
    const back = t0 + 100 + 3 * GRACE + 10;
    expect((await settler.tick(back)).apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(status.deferredSince).toBeUndefined();
    expect(status.failingSince).toBe(t0 + 3 * GRACE + 10);
    expect(paymentNeededShown()).toBe(false);
    await settler.tick(back + GRACE - 100 - 1);
    expect(paymentNeededShown()).toBe(false);
    const late = await settler.tick(back + GRACE - 100);
    expect(late.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
  });

  // D-073: during an outage the settler still pays the reports the platform accepted before it. A customer who fixes
  // their side then must not stay on the payment-needed page until the platform is back.
  it("a customer who fixes their side during a platform outage leaves the payment-needed page at the next payment", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    payer.budgetResult = { spendable: 0n, problem: "spend_limit" };
    const t0 = 10_000;
    await settler.tick(t0);
    expect(usage.length).toBe(1);
    expect((await settler.tick(t0 + GRACE)).paymentNeeded).toBe(true);
    // The platform goes down; the customer raises the limit. The accepted report is paid, the new one waits.
    platformDown = true;
    payer.budgetResult = { spendable: 1_000_000_000n };
    await ledger.record("crm", "app_hour", 60n, t0 + GRACE + 1);
    const r = await settler.tick(t0 + GRACE + 60);
    expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" }), { app: "*", result: "failed", reason: "usage_not_submitted" }]);
    expect(r.paymentNeeded).toBe(false);
    expect(caddy.current).toBe(CADDYFILE);
    expect(status).toMatchObject({ failingSince: null, deferredSince: t0 + GRACE + 60 });
    // Still deferred, still no grace clock; then the platform is back and the waiting report is paid.
    expect((await settler.tick(t0 + 5 * GRACE)).paymentNeeded).toBe(false);
    platformDown = false;
    const back = await settler.tick(t0 + 5 * GRACE + 60);
    expect(back.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" })]);
    expect(ledger.unpaid()).toEqual([]);
    expect(status.deferredSince).toBeUndefined();
  });

  // D-073: only failures on the customer's side count toward the grace period (D-048 billing policy), and a platform
  // outage at the same time does not hide them.
  describe("customer-side failures count toward the grace period, also during a platform outage", () => {
    const cases: { name: string; reason: string; arrange: () => void }[] = [
      { name: "a missing access key", reason: "access_key_missing", arrange: () => (payer.budgetResult = { spendable: 0n, problem: "access_key_missing" }) },
      { name: "a revoked access key", reason: "access_key_revoked", arrange: () => (payer.budgetResult = { spendable: 0n, problem: "access_key_revoked" }) },
      { name: "an expired access key", reason: "access_key_expired", arrange: () => (payer.budgetResult = { spendable: 0n, problem: "access_key_expired" }) },
      { name: "an exhausted limit", reason: "spend_limit", arrange: () => (payer.budgetResult = { spendable: 0n, problem: "spend_limit" }) },
      { name: "too little balance", reason: "insufficient_balance", arrange: () => (payer.budgetResult = { spendable: 0n, problem: "insufficient_balance" }) },
      { name: "a reverted payment", reason: "tx_failed", arrange: () => (payer.failNext = 1_000) },
      {
        name: "a payment whose estimate reverts",
        reason: "estimate_reverted",
        arrange: () =>
          (payer.feeReserve = async () => {
            throw new Error("execution reverted: Unauthorized");
          }),
      },
    ];
    for (const c of cases) {
      it(c.name, async () => {
        // A report the platform accepts, whose payment fails on the customer's side; then the platform goes down too.
        await ledger.record("crm", "app_hour", 3600n, 1001);
        c.arrange();
        const t0 = 10_000;
        const first = await settler.tick(t0);
        expect(first.apps).toEqual([{ app: "crm", result: "failed", reason: c.reason }]);
        expect(usage.length).toBe(1);
        platformDown = true;
        await ledger.record("crm", "app_hour", 60n, t0 + 1);
        const r = await settler.tick(t0 + 60);
        expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: c.reason }, { app: "*", result: "failed", reason: "usage_not_submitted" }]);
        expect(status.failingSince).toBe(t0);
        expect(status.deferredSince).toBeUndefined();
        expect((await settler.tick(t0 + GRACE - 1)).paymentNeeded).toBe(false);
        expect((await settler.tick(t0 + GRACE)).paymentNeeded).toBe(true);
        expect(paymentNeededShown()).toBe(true);
        expect(status.lastOutcome).toBe(c.reason);
      });
    }

    it("the platform-side reasons are exactly those D-073 defers", () => {
      expect([...PLATFORM_SIDE_FAILURES].sort()).toEqual(["deployment_not_registered", "fee_splitter_paused", "ledger_unverified", "usage_not_submitted"]);
      for (const c of cases) expect(PLATFORM_SIDE_FAILURES.has(c.reason)).toBe(false);
    });
  });

  it("voids a report the platform refuses as overlapping a stored one, and never pays it", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    const cut = await ledger.closePeriod(1500);
    const stored = `0x${"5e".repeat(32)}`;
    const conflict = new HttpError(409, JSON.stringify({ error: { code: "conflict", message: "overlaps", detail: { usageHash: stored, periodStart: 900, periodEnd: 1600 } } }), "/v1/usage");
    let calls = 0;
    const platform: PlatformClient = {
      postEvidence: async () => ({ deploymentId: "0x" }),
      postUsage: async () => {
        calls++;
        if (calls === 1) throw conflict;
        return undefined;
      },
      postHealth: async () => undefined,
    };
    settler = new Settler({ ledger, payer, platform, status, graceSec: GRACE, save: async () => {}, log: silentLogger });
    await ledger.record("crm", "app_hour", 60n, 1600);
    const r = await settler.tick(2000);
    expect(ledger.state.reports.find((x) => x.usageHash === cut?.usageHash)?.void).toBe(true);
    // The void report is not paid and does not block the next one, which was submitted and paid.
    expect(r.submitted).toBe(1);
    expect(payer.paid.flat().map((l) => l.usageHash)).not.toContain(cut?.usageHash);
    expect(r.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" })]);
    expect(ledger.totals().metered).toBe(BigInt(ledger.state.reports.find((x) => !x.void)?.payments.crm?.fee ?? "0"));
    // A 409 that names the report itself means the platform already has it: submitted.
    await ledger.record("crm", "app_hour", 60n, 2001);
    const again = await ledger.closePeriod(2100);
    let same = true;
    settler = new Settler({
      ledger,
      payer,
      platform: {
        ...platform,
        postUsage: async () => {
          if (same) {
            same = false;
            throw new HttpError(409, JSON.stringify({ error: { code: "conflict", detail: { usageHash: again?.usageHash } } }), "/v1/usage");
          }
        },
      },
      status,
      graceSec: GRACE,
      save: async () => {},
      log: silentLogger,
    });
    await settler.tick(2200);
    expect(ledger.state.reports.find((x) => x.usageHash === again?.usageHash)).toMatchObject({ submitted: true });
    expect(ledger.state.reports.find((x) => x.usageHash === again?.usageHash)?.void).toBeUndefined();
  });

  it("cuts nothing and fails closed while the ledger waits for its boot rebuild", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001);
    ledger.holdForRebuild();
    let readable = false;
    settler = new Settler({
      ledger,
      payer,
      platform: { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async (b) => usage.push(b), postHealth: async () => undefined },
      status,
      graceSec: GRACE,
      save: async () => {},
      log: silentLogger,
      rebuild: async () => {
        if (readable) ledger.adopt([]);
        return readable;
      },
    });
    const r = await settler.tick(2000);
    expect(r).toMatchObject({ outcome: "failed", reportCut: false, apps: [{ app: "*", result: "failed", reason: "ledger_unverified" }] });
    expect(usage).toEqual([]);
    readable = true;
    const r2 = await settler.tick(2100);
    // Nothing was signed for this deployment, so the held usage is kept and billed now.
    expect(r2.reportCut).toBe(true);
    expect(r2.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" })]);
  });

  // Review L2: legs the settler cannot pay stayed in reserved_for_fees for good.
  it("records the legs it cannot pay and why", async () => {
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000
    await ledger.record("llm-gateway", "tokens", 50_000n, 1002); // 10_000
    await ledger.closePeriod(1500);
    payer.cap = 40_000n; // the crm leg is above the lowered cap
    payer.inDeployment = false; // and the gateway leg's app is not in the deployment onchain
    await settler.tick(2000);
    expect(Object.values(status.unpayable ?? {}).sort()).toEqual(["not_in_deployment", "over_payment_cap"]);
    payer.cap = 5_000_000n;
    payer.inDeployment = true;
    await settler.tick(2100);
    expect(status.unpayable).toEqual({});
    expect(ledger.unpaid()).toEqual([]);
  });

  // Review I6: in enclave-account mode nothing onchain limits fee settlement, so the agent's own limit does.
  it("caps fee settlement by the agent's spend limit when the chain does not enforce one", async () => {
    let left = 30_000n;
    settler = new Settler({ ledger, payer, platform: { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async () => undefined, postHealth: async () => undefined }, status, graceSec: GRACE, save: async () => {}, log: silentLogger, feeLimit: () => left });
    await ledger.record("crm", "app_hour", 3600n, 1001); // 50_000
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "spend_limit" }]);
    expect(payer.paid).toEqual([]);
    left = 1_000_000n;
    expect((await settler.tick(2100)).apps).toEqual([expect.objectContaining({ app: "crm", result: "paid" })]);
  });

  describe("what settlement takes from the shared spend limit (review M4)", () => {
    let budget: SpendBudget;
    beforeEach(() => {
      budget = new SpendBudget({ limit: 2_000_000n, state: emptyBudgetState(1000), feeReserve: () => 0n });
      settler = new Settler({ ledger, payer, platform: { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async () => undefined, postHealth: async () => undefined }, status, graceSec: GRACE, save: async () => {}, log: silentLogger, spend: budget });
    });

    it("a paid batch counts its fees and network fee, and teaches the network fee per transaction", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      await settler.tick(2000);
      expect(budget.state.fees).toBe((50_000n + payer.networkFee).toString());
      expect(budget.state.networkFeePerTx).toBe(payer.networkFee.toString());
    });

    it("a reverted batch counts the network fee it paid", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.failNextAs = "reverted";
      const r = await settler.tick(2000);
      expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "tx_failed" }]);
      expect(budget.state.fees).toBe(payer.networkFee.toString());
      expect(ledger.unpaid().length).toBe(1);
    });

    it("a batch whose receipt never came counts its fees plus the fee reserve until the receipt shows", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.failNextAs = "unknown";
      const r = await settler.tick(2000);
      expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "tx_unconfirmed" }]);
      const [pending] = budget.pendingFees();
      expect(pending).toMatchObject({ owed: "50000", counted: (50_000n + payer.reserve).toString() });
      expect(budget.state.fees).toBe((50_000n + payer.reserve).toString());
      // It landed after all: the next tick finds the receipt, corrects the count, and sees the leg paid onchain
      // without paying it again (before the fix, nothing was ever counted for it).
      const [leg] = ledger.unpaid();
      payer.payDirectly(leg!.usageHash, leg!.appId, 50_000n);
      payer.receipts.set(pending!.txHash, { status: "success", networkFee: 1_500n });
      const r2 = await settler.tick(2100);
      expect(r2).toMatchObject({ outcome: "settled", apps: [] });
      expect(ledger.unpaid()).toEqual([]);
      expect(budget.pendingFees()).toEqual([]);
      expect(budget.state.fees).toBe("51500");
      expect(payer.paid.length).toBe(0);
    });

    it("stops looking for a receipt after a while and keeps the count", async () => {
      await ledger.record("crm", "app_hour", 3600n, 1001);
      payer.failNextAs = "unknown";
      await settler.tick(2000);
      await settler.tick(2000 + PENDING_GIVE_UP_SEC - 1);
      expect(budget.pendingFees().length).toBe(1);
      const counted = budget.state.fees;
      await settler.tick(2000 + PENDING_GIVE_UP_SEC);
      expect(budget.pendingFees()).toEqual([]);
      expect(BigInt(budget.state.fees) >= BigInt(counted)).toBe(true);
    });
  });
});

// payments-3, ported from the pre-publish verifier's repro (verify-payments3.test.ts), with the production grace period
// (24 h) against an access key whose periodic limit is below the app-hour fees. The settler used to count a payment
// that cleared part of the backlog as a success: each limit period's first payment ended the failure streak, so a
// daily limit never reached the payment-needed page while the debt grew, and a weekly one left it at the roll.
describe("payments-3: a spend limit below the fees (production grace period)", () => {
  const prod = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"));
  const PROD_GRACE = prod.grace_period_minutes * 60;
  const HOUR = 3600;
  const t0 = 1_000_000;
  const apps = ["crm", "coding-agent", "internal-tools"];

  /** The access key's periodic limit as the keychain enforces it, and FeeSplitter's daily cap, which rolls every day. */
  class PeriodicKeyPayer extends FakePayer {
    now = t0;
    periodEnd: number;
    remaining: bigint;
    dayEnd = t0 + 86_400;
    constructor(
      public keyLimit: bigint,
      readonly period: number,
    ) {
      super();
      this.periodEnd = t0 + period;
      this.remaining = keyLimit;
      this.daily = 20_000_000n;
    }
    roll() {
      while (this.now >= this.periodEnd) {
        this.periodEnd += this.period;
        this.remaining = this.keyLimit;
      }
      while (this.now >= this.dayEnd) {
        this.dayEnd += 86_400;
        this.daily = 20_000_000n;
      }
    }
    override async dailyRemaining() {
      this.roll();
      return super.dailyRemaining();
    }
    override async budget(reserve: bigint): Promise<Budget> {
      this.roll();
      const s = this.remaining - reserve;
      return s > 0n ? { spendable: s, binding: "spend_limit" } : { spendable: 0n, problem: "spend_limit", binding: "spend_limit" };
    }
    override async pay(lines: PaymentLine[]) {
      this.roll();
      const sum = lines.reduce((s, l) => s + l.amount, 0n);
      if (sum + this.networkFee > this.remaining) throw new Error("execution reverted: SpendingLimitExceeded");
      const r = await super.pay(lines);
      this.remaining -= sum + this.networkFee;
      return r;
    }
  }

  type Row = { h: number; outcome: string; failingSince: number | null; paymentNeeded: boolean; backlog: bigint };

  function harness(payer: PeriodicKeyPayer) {
    const ledger = new Ledger(emptyLedgerState(t0), {
      deploymentId: `0x${"de".repeat(32)}`,
      apps,
      schedule: feeScheduleFromDefaults(prod),
      domain: usageDomain(`0x${"04".repeat(20)}`, 4217),
      enclaveKey: deriveEnclavePrivateKey(`0x${"01".repeat(32)}`),
      perPaymentCap: () => payer.cap,
    });
    const status: PaymentStatus = { failingSince: null, paymentNeeded: false };
    const platform: PlatformClient = { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async () => undefined, postHealth: async () => undefined };
    const settler = new Settler({ ledger, payer, platform, status, graceSec: PROD_GRACE, save: async () => {}, log: silentLogger });
    const rows: Row[] = [];
    /** Hourly settlements from hour `from` to `to`, every app accruing an app-hour. */
    const run = async (from: number, to: number) => {
      for (let h = from; h <= to; h++) {
        const now = t0 + h * HOUR;
        for (const a of apps) await ledger.record(a, "app_hour", 3600n, now - 1);
        payer.now = now;
        const r = await settler.tick(now);
        rows.push({ h, outcome: r.outcome, failingSince: status.failingSince, paymentNeeded: status.paymentNeeded, backlog: ledger.unpaid().reduce((s, e) => s + e.fee, 0n) });
      }
    };
    return { ledger, status, rows, run };
  }

  it("uses the 24 h production grace period and 3.60 USD of app-hours a day", async () => {
    expect(PROD_GRACE).toBe(86_400);
    const { ledger } = harness(new PeriodicKeyPayer(0n, 86_400));
    for (const a of apps) await ledger.record(a, "app_hour", 86_400n, t0 + 1);
    await ledger.closePeriod(t0 + 2);
    expect(ledger.unpaid().reduce((s, e) => s + e.fee, 0n)).toBe(3_600_000n);
  });

  it("a daily limit of 2 USD reaches the payment-needed page within the grace period of the streak that never clears", async () => {
    const payer = new PeriodicKeyPayer(2_000_000n, 86_400);
    const { rows, run } = harness(payer);
    await run(1, 24 * 6);
    // The streak ends only at a settlement that leaves nothing behind (before the fix: at every daily roll).
    for (const r of rows) if (r.failingSince === null) expect(r.backlog).toBe(0n);
    const lastClear = rows.filter((r) => r.backlog === 0n).at(-1)!.h;
    const start = rows.find((r) => r.h > lastClear && r.failingSince !== null)!;
    const shown = rows.find((r) => r.paymentNeeded);
    expect(shown).toBeDefined();
    expect(shown!.h).toBeLessThanOrEqual(start.h + PROD_GRACE / HOUR + 1);
    // Once shown, the page stays: the debt is never paid, and the backlog behind it is under one day of fees.
    for (const r of rows.filter((x) => x.h >= shown!.h)) expect(r.paymentNeeded).toBe(true);
    expect(shown!.backlog < 3_600_000n).toBe(true);
    expect(rows.filter((r) => r.h % 24 === 0 && r.h >= shown!.h).every((r) => r.outcome === "partial")).toBe(true);
  });

  it("a weekly limit of 12 USD keeps the payment-needed page past the weekly roll until the backlog is paid", async () => {
    const payer = new PeriodicKeyPayer(12_000_000n, 7 * 86_400);
    const { ledger, status, rows, run } = harness(payer);
    await run(1, 24 * 8);
    const shown = rows.find((r) => r.paymentNeeded)!;
    expect(shown).toBeDefined();
    const roll = rows.find((r) => r.h === 168)!;
    expect(roll.outcome).toBe("partial");
    // Before the fix the first payment after the roll restored the routes with about 12 USD still unpaid.
    for (const r of rows.filter((x) => x.h >= shown.h)) expect(r.paymentNeeded).toBe(true);
    expect(rows.at(-1)!.backlog > 0n).toBe(true);
    // The customer raises the limit: the backlog is paid ten legs per app per settlement, and the routes come back
    // with the settlement that leaves nothing overdue.
    payer.keyLimit = 1_000_000_000n;
    payer.remaining = payer.keyLimit;
    const before = rows.length;
    for (let h = 24 * 8 + 1; ledger.unpaid().length > 0 && h < 24 * 9; h++) await run(h, h);
    const recovery = rows.slice(before);
    expect(recovery.length).toBeGreaterThan(1);
    expect(recovery.slice(0, -1).every((r) => r.paymentNeeded && r.outcome === "partial")).toBe(true);
    expect(recovery.at(-1)).toMatchObject({ paymentNeeded: false, failingSince: null, outcome: "settled" });
    expect(status.paymentNeeded).toBe(false);
  });
});

// payments-4, ported from the pre-publish verifier's repro (verify-payments4.test.ts): a healthy key and balance, the
// operator's FeeSplitter pause, the production grace period. The repro's payer reports the pause only in its revert
// message, the way viem decodes it with the ABI. Before the fix the page showed at hour 25.
describe("payments-4: a FeeSplitter pause never puts a customer on the payment-needed page", () => {
  const prod = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"));
  class PausedSplitterPayer extends FakePayer {
    override async splitterPaused() {
      return false;
    }
    override async feeReserve(lines: PaymentLine[]) {
      if (this.paused) throw new Error('The contract function "payFees" reverted. Error: EnforcedPause()');
      return super.feeReserve(lines);
    }
  }

  it("26 hours of pause defer settlement; the backlog is paid after the unpause", async () => {
    const t0 = 2_000_000;
    const payer = new PausedSplitterPayer();
    payer.paused = true;
    const ledger = new Ledger(emptyLedgerState(t0), {
      deploymentId: `0x${"de".repeat(32)}`,
      apps: ["crm"],
      schedule: feeScheduleFromDefaults(prod),
      domain: usageDomain(`0x${"04".repeat(20)}`, 4217),
      enclaveKey: deriveEnclavePrivateKey(`0x${"01".repeat(32)}`),
      perPaymentCap: () => payer.cap,
    });
    const status: PaymentStatus = { failingSince: null, paymentNeeded: false };
    const platform: PlatformClient = { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async () => undefined, postHealth: async () => undefined };
    const settler = new Settler({ ledger, payer, platform, status, graceSec: prod.grace_period_minutes * 60, save: async () => {}, log: silentLogger });
    let first: unknown;
    for (let h = 1; h <= 26; h++) {
      const now = t0 + h * 3600;
      await ledger.record("crm", "app_hour", 3600n, now - 1);
      const r = await settler.tick(now);
      first ??= r.apps;
      expect(r.paymentNeeded).toBe(false);
    }
    expect(first).toEqual([{ app: "crm", result: "failed", reason: "fee_splitter_paused" }]);
    expect(status).toMatchObject({ failingSince: null, deferredSince: t0 + 3600, lastOutcome: "fee_splitter_paused" });
    payer.paused = false;
    const outcomes: string[] = [];
    for (let h = 27; ledger.unpaid().length > 0 && h < 40; h++) outcomes.push((await settler.tick(t0 + h * 3600)).outcome);
    expect(outcomes).toEqual(["partial", "partial", "settled"]);
    expect(status).toMatchObject({ failingSince: null, paymentNeeded: false });
    expect(status.deferredSince).toBeUndefined();
  });
});
