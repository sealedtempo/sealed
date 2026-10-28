// Settlement (spec 5.6 steps 6-8, 7.3): every interval, close the usage period, submit signed
// reports, and pay each app's unpaid reports in one transaction within the FeeSplitter daily cap
// and the payer's budget. A (report, app) leg is settled only when FeeSplitter's usagePaid reaches
// the report's fee: a leg paid short (the customer can pay first with any amount) is topped up with
// the shortfall, so it is never settled for less. Failures that last beyond the grace period switch
// Caddy to the payment-needed page; the next successful settlement restores it.
import type { Hex } from "@sealed/core";
import type { PaymentGate } from "../caddy.js";
import type { PlatformClient } from "../evidence.js";
import { errorFields, type Logger } from "../log.js";
import type { Ledger, UnpaidEntry } from "../metering/ledger.js";
import type { PaymentStatus } from "../state.js";
import type { FeePayer, PaymentLine } from "./feePayer.js";

export type AppOutcome =
  | { app: string; result: "paid"; txHash: Hex; amount: bigint; reports: number }
  | { app: string; result: "deferred"; reason: "daily_cap" | "not_in_deployment" }
  | { app: string; result: "failed"; reason: string };

export interface SettlementResult {
  at: number;
  reportCut: boolean;
  submitted: number;
  outcome: "nothing_due" | "deployment_not_active" | "settled" | "partial" | "failed";
  apps: AppOutcome[];
  paymentNeeded: boolean;
}

/** An unpaid leg with what FeeSplitter already recorded for it and what is still owed (fee - paid). */
type Due = UnpaidEntry & { paid: bigint; owed: bigint };

export interface SettlerDeps {
  ledger: Ledger;
  payer: FeePayer;
  platform: PlatformClient;
  gate?: PaymentGate;
  status: PaymentStatus;
  graceSec: number;
  save: () => Promise<void>;
  log: Logger;
}

export class Settler {
  constructor(private readonly d: SettlerDeps) {}

  private async submitReports(): Promise<number> {
    let n = 0;
    for (const r of this.d.ledger.unsubmitted()) {
      try {
        await this.d.platform.postUsage({ report: r.report, signature: r.signature });
        this.d.ledger.markSubmitted(r.usageHash);
        n++;
      } catch (err) {
        this.d.log.warn("usage report submission failed", { usageHash: r.usageHash, ...errorFields(err) });
        break;
      }
    }
    return n;
  }

  /** Groups unpaid entries per app, oldest app first, keeping FIFO order inside each app. */
  private byApp(entries: UnpaidEntry[]): Map<string, UnpaidEntry[]> {
    const m = new Map<string, UnpaidEntry[]>();
    for (const e of entries) m.set(e.app, [...(m.get(e.app) ?? []), e]);
    return m;
  }

  private async payApps(now: number): Promise<AppOutcome[]> {
    const { ledger, payer, log } = this.d;
    const outcomes: AppOutcome[] = [];
    let daily = await payer.dailyRemaining();
    for (const [app, all] of this.byApp(ledger.unpaid())) {
      const due: Due[] = [];
      for (const e of all) {
        const paid = await payer.paidAmount(e.usageHash, e.appId);
        if (paid >= e.fee) {
          ledger.markPaid(e.usageHash, app, undefined, now);
          continue;
        }
        if (paid > 0n) log.warn("usage paid short onchain, topping up to the report's fee", { app, usageHash: e.usageHash, paid: paid.toString(), fee: e.fee.toString() });
        due.push({ ...e, paid, owed: e.fee - paid });
      }
      if (due.length === 0) continue;
      if (!(await payer.appInDeployment((due[0] as Due).appId))) {
        outcomes.push({ app, result: "deferred", reason: "not_in_deployment" });
        continue;
      }
      try {
        const asLines = (es: Due[]): PaymentLine[] => es.map((e) => ({ appId: e.appId, amount: e.owed, usageHash: e.usageHash, paid: e.paid }));
        const reserve = await payer.feeReserve(asLines(due));
        const budget = await payer.budget(reserve);
        const limit = budget.spendable < daily ? budget.spendable : daily;
        const chosen: Due[] = [];
        let sum = 0n;
        for (const e of due) {
          if (sum + e.owed > limit) break;
          chosen.push(e);
          sum += e.owed;
        }
        if (chosen.length === 0) {
          const first = (due[0] as Due).owed;
          if (daily < first && budget.spendable >= first) {
            outcomes.push({ app, result: "deferred", reason: "daily_cap" });
          } else {
            outcomes.push({ app, result: "failed", reason: budget.problem ?? "insufficient_balance" });
          }
          continue;
        }
        const { txHash, gasUsed } = await payer.pay(asLines(chosen));
        for (const e of chosen) ledger.markPaid(e.usageHash, app, txHash, now);
        daily -= sum;
        const topUps = chosen.filter((e) => e.paid > 0n).length;
        log.info("fees paid", { app, amount: sum.toString(), reports: chosen.length, topUps, txHash, gasUsed, mode: payer.mode });
        outcomes.push({ app, result: "paid", txHash, amount: sum, reports: chosen.length });
      } catch (err) {
        log.warn("fee payment failed", { app, ...errorFields(err) });
        outcomes.push({ app, result: "failed", reason: "tx_failed" });
      }
    }
    return outcomes;
  }

  async tick(now: number): Promise<SettlementResult> {
    const { ledger, status, log } = this.d;
    const reportCut = (await ledger.closePeriod(now)) !== undefined;
    const submitted = await this.submitReports();
    let apps: AppOutcome[] = [];
    let outcome: SettlementResult["outcome"];
    if (ledger.unpaid().length === 0) outcome = "nothing_due";
    else if (!(await this.safe(() => this.d.payer.deploymentActive(), false))) outcome = "deployment_not_active";
    else {
      try {
        apps = await this.payApps(now);
      } catch (err) {
        log.warn("settlement failed", errorFields(err));
        apps = [{ app: "*", result: "failed", reason: "rpc_error" }];
      }
      const failed = apps.some((a) => a.result === "failed");
      const paid = apps.some((a) => a.result === "paid");
      outcome = failed ? (paid ? "partial" : "failed") : "settled";
    }
    status.lastAttemptAt = now;
    status.lastOutcome = apps.find((a) => a.result === "failed")?.reason ?? outcome;
    const failedNow = apps.some((a) => a.result === "failed");
    if (failedNow) status.failingSince ??= now;
    else status.failingSince = null;
    if (apps.some((a) => a.result === "paid")) status.lastPaidAt = now;
    await this.updateGate(now, failedNow, ledger.unpaid().length === 0 || apps.some((a) => a.result === "paid"));
    await this.d.save();
    return { at: now, reportCut, submitted, outcome, apps, paymentNeeded: status.paymentNeeded };
  }

  private async updateGate(now: number, failedNow: boolean, recovered: boolean): Promise<void> {
    const { status, gate, log } = this.d;
    try {
      if (status.failingSince !== null && now - status.failingSince >= this.d.graceSec) {
        if (!status.paymentNeeded) log.warn("payments failing beyond the grace period, switching to the payment-needed page", { failingSince: status.failingSince });
        status.paymentNeeded = true;
        await gate?.enable();
      } else if (status.paymentNeeded && !failedNow && recovered) {
        await gate?.disable();
        status.paymentNeeded = false;
        log.info("payment succeeded, app routes restored");
      } else if (status.paymentNeeded) {
        await gate?.enable();
      }
    } catch (err) {
      log.error("could not update Caddy routes", errorFields(err));
    }
  }

  private async safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      this.d.log.warn("chain read failed", errorFields(err));
      return fallback;
    }
  }
}
