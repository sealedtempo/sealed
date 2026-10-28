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
import { PENDING_GIVE_UP_SEC, Settler } from "../src/payments/settler.js";
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
    expect(r1.apps).toEqual([expect.objectContaining({ app: "crm", result: "paid", amount: 25_000n })]);
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
    payer.rpcDown = false;
    const r = await settler.tick(t0 + 48 * 3600);
    expect(r.outcome).toBe("settled");
    expect(r.paymentNeeded).toBe(false);
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

  it("a deployment that never gets registered goes to payment-needed one grace period after its oldest unpaid report", async () => {
    payer.deployment = "none";
    await ledger.record("crm", "app_hour", 3600n, 1001);
    const r1 = await settler.tick(2000);
    expect(r1.outcome).toBe("deployment_not_registered");
    expect(status.failingSince).toBe(2000);
    expect(r1.paymentNeeded).toBe(false);
    await ledger.record("crm", "app_hour", 60n, 2001);
    expect((await settler.tick(2000 + GRACE - 1)).paymentNeeded).toBe(false);
    const r3 = await settler.tick(2000 + GRACE);
    expect(r3.paymentNeeded).toBe(true);
    expect(paymentNeededShown()).toBe(true);
    // Registered at last: the backlog is paid and the routes come back.
    payer.deployment = "active";
    const r4 = await settler.tick(2000 + GRACE + 60);
    expect(r4.outcome).toBe("settled");
    expect(r4.paymentNeeded).toBe(false);
    expect(ledger.unpaid()).toEqual([]);
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
    expect(r.apps).toEqual([expect.objectContaining({ result: "paid", amount: 200_000n, reports: 2 })]);
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
      throw new Error("execution reverted: EnforcedPause");
    };
    const r = await settler.tick(2000);
    expect(r.apps).toEqual([{ app: "crm", result: "failed", reason: "estimate_reverted" }]);
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
