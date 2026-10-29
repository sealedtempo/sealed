// payments-7: while the routes show the payment-needed page the customer cannot reach the apps, so the health
// poller must not bill their app-hours, then or after the routes come back. Before the fix the poller billed every
// healthy heartbeat app for the whole lockout (the review's repro: 4.80 USD of crm after 96 h, 72 h of it locked out).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { appId, deriveEnclavePrivateKey, feeScheduleFromDefaults, parseDefaults, usageDomain } from "@sealed/core";
import { describe, expect, it } from "vitest";
import type { AppMeta } from "../src/context.js";
import type { PlatformClient } from "../src/evidence.js";
import { silentLogger } from "../src/log.js";
import { AppHealthPoller } from "../src/metering/appHealth.js";
import { emptyLedgerState, Ledger } from "../src/metering/ledger.js";
import { Settler } from "../src/payments/settler.js";
import type { PaymentStatus } from "../src/state.js";
import { FakePayer } from "./helpers/fakePayer.js";

const defaults = parseDefaults(readFileSync(join(import.meta.dirname, "../../../config/defaults.yaml"), "utf8"));
const GRACE = defaults.grace_period_minutes * 60;
const CRM_PER_HOUR = 50_000n;

function world(t0: number) {
  const payer = new FakePayer();
  const ledger = new Ledger(emptyLedgerState(t0), {
    deploymentId: `0x${"de".repeat(32)}`,
    apps: ["crm"],
    schedule: feeScheduleFromDefaults(defaults),
    domain: usageDomain(`0x${"04".repeat(20)}`, 4217),
    enclaveKey: deriveEnclavePrivateKey(`0x${"01".repeat(32)}`),
    perPaymentCap: () => payer.cap,
  });
  const status: PaymentStatus = { failingSince: null, paymentNeeded: false };
  const platform: PlatformClient = { postEvidence: async () => ({ deploymentId: "0x" }), postUsage: async () => undefined, postHealth: async () => undefined };
  const settler = new Settler({ ledger, payer, platform, status, graceSec: GRACE, save: async () => {}, log: silentLogger });
  const crm = {
    id: "crm",
    appId: appId("crm"),
    releaseId: `0x${"c1".repeat(32)}`,
    metering: { unit: "app_hour", source: "heartbeat" },
    healthcheck: "http://172.30.0.16:3000/healthz",
    serviceIps: [],
  } as unknown as AppMeta;
  const poller = new AppHealthPoller([crm], { ledger, log: silentLogger, intervalSec: 30, probe: async () => true, billable: () => !status.paymentNeeded });
  const billed = () => ledger.state.reports.reduce((s, r) => s + BigInt(r.payments.crm?.fee ?? "0"), 0n) + ledger.openFee("crm");
  return { payer, ledger, status, settler, poller, billed };
}

describe("payments-7: app-hours are not billed behind the payment-needed page", () => {
  it("bills nothing for three locked-out days, and only the hours after the routes come back", async () => {
    const t0 = 3_000_000;
    const w = world(t0);
    w.payer.budgetResult = { spendable: 0n, problem: "access_key_expired" };
    let lockedAt: number | undefined;
    let billedAtLock = 0n;
    for (let h = 0; h < 24 * 4; h++) {
      for (let s = 0; s < 3600; s += 30) await w.poller.pollOnce(t0 + h * 3600 + s);
      const r = await w.settler.tick(t0 + (h + 1) * 3600);
      if (r.paymentNeeded && lockedAt === undefined) {
        lockedAt = h + 1;
        billedAtLock = w.billed();
      }
    }
    expect(w.status.paymentNeeded).toBe(true);
    // The grace period is 24 h: the routes switch after the 25th settlement, and nothing is billed after that.
    expect(lockedAt).toBe(25);
    expect(billedAtLock).toBeLessThanOrEqual(25n * CRM_PER_HOUR);
    expect(w.billed()).toBe(billedAtLock);
    expect(w.ledger.openFee("crm")).toBe(0n);
    // The poller still reports the app as healthy.
    expect(w.poller.status()).toEqual({ crm: "healthy" });

    // The customer authorizes a new key: the next settlement pays and restores the routes.
    w.payer.budgetResult = { spendable: 1_000_000_000n };
    const end = t0 + 96 * 3600;
    const back = await w.settler.tick(end + 1);
    expect(back.paymentNeeded).toBe(false);
    // At most 10 legs per transaction: the backlog of 25 hourly legs takes three settlements.
    for (let i = 2; i <= 3; i++) await w.settler.tick(end + i);
    expect(w.ledger.unpaid()).toEqual([]);
    expect(w.payer.paid.flat().reduce((s, l) => s + l.amount, 0n)).toBe(billedAtLock);
    // The first billed interval after the lockout starts at the last poll (30 s before the routes came back), not
    // at the lock: an hour of polls bills an hour and at most one poll interval, never the three locked-out days.
    for (let s = 30; s <= 3600; s += 30) await w.poller.pollOnce(end + s);
    const after = w.billed() - billedAtLock;
    expect(after).toBeGreaterThanOrEqual(CRM_PER_HOUR);
    expect(after).toBeLessThanOrEqual(CRM_PER_HOUR + (CRM_PER_HOUR * 30n) / 3600n + 1n);
  });

  it("without the gate (no billable dependency) the poller bills every healthy interval", async () => {
    const t0 = 3_000_000;
    const w = world(t0);
    const ungated = new AppHealthPoller([...(w.poller as unknown as { apps: AppMeta[] }).apps], { ledger: w.ledger, log: silentLogger, intervalSec: 30, probe: async () => true });
    w.status.paymentNeeded = true;
    for (let s = 0; s <= 3600; s += 30) await ungated.pollOnce(t0 + s);
    expect(w.billed()).toBe(CRM_PER_HOUR);
  });
});
