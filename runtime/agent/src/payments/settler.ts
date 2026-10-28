// Settlement (spec 5.6 steps 6-8, 7.3): every interval, close the usage period, submit signed
// reports, and pay each app's unpaid reports in one transaction within the FeeSplitter daily cap
// and the payer's budget. A (report, app) leg is settled only when FeeSplitter's usagePaid reaches
// the report's fee: a leg paid short (the customer can pay first with any amount) is topped up with
// the shortfall, so it is never settled for less.
//
// Billing fails closed. Anything that keeps due fees from being paid counts as a failure: a chain
// read error (the customer controls the VPC firewall and can block the RPC), a deployment that is
// still not registered (measured from the oldest unpaid report, so blocking the platform API does
// not help either), a reverted estimate or transaction, a leg that cannot be topped up. Failures that
// last the grace period switch Caddy to the measured payment-needed Caddyfile; a Closed deployment
// (terminal) switches at once. The next successful settlement restores the normal Caddyfile. Only
// limits the operator sets onchain are deferrals: the daily cap, and legs above a lowered
// per-payment cap (reported as overCap, never paid at that cap).
//
// D-062: a report is paid only once the platform has accepted it, so every paid period is among the
// stored reports the agent rebuilds its ledger from after a disk rollback. Each tick first rebuilds
// (the agent reads the platform's stored reports), cuts nothing while this boot's ledger is not yet
// rebuilt, saves a cut report before it leaves the VM, and voids a report the platform refuses as
// overlapping a stored one. A report that cannot be submitted is a failure like any other, so blocking
// the platform API does not stop billing from failing closed.
import type { Hex } from "@sealed/core";
import type { CaddySwitch } from "../caddy.js";
import type { PlatformClient } from "../evidence.js";
import { HttpError } from "../http.js";
import { errorFields, type Logger } from "../log.js";
import type { Ledger, UnpaidEntry } from "../metering/ledger.js";
import type { PaymentStatus } from "../state.js";
import { type Budget, type DeploymentStatus, type FeePayer, MAX_LINES_PER_TX, PaymentError, type PaymentLine } from "./feePayer.js";

/**
 * Where settlement records what it took from the shared spend limit (D-048, the SpendBudget). Every broadcast
 * transaction is counted: a paid one with its fees and network fee, a reverted one with its network fee, one
 * whose outcome is unknown with its fees plus the fee reserve until its receipt shows (review M4).
 */
export interface SpendRecorder {
  recordFees(amount: bigint, now: number, networkFee?: bigint): void;
  recordPendingFee(txHash: string, owed: bigint, counted: bigint, now: number): void;
  pendingFees(): Array<{ txHash: string; owed: string; counted: string; at: number }>;
  resolvePendingFee(txHash: string, actual: bigint, now: number): void;
}

/** A transaction with no receipt after this long is no longer looked for; what was counted for it stays counted. */
export const PENDING_GIVE_UP_SEC = 6 * 3600;

export type AppOutcome =
  | { app: string; result: "paid"; txHash: Hex; amount: bigint; reports: number }
  | { app: string; result: "deferred"; reason: "daily_cap" | "over_payment_cap" }
  | { app: string; result: "failed"; reason: string };

export interface SettlementResult {
  at: number;
  reportCut: boolean;
  submitted: number;
  outcome: "nothing_due" | "deployment_not_registered" | "deployment_closed" | "settled" | "partial" | "failed";
  apps: AppOutcome[];
  paymentNeeded: boolean;
}

/** An unpaid leg with what FeeSplitter already recorded for it and what is still owed (fee - paid). */
type Due = UnpaidEntry & { paid: bigint; owed: bigint };

export interface SettlerDeps {
  ledger: Ledger;
  payer: FeePayer;
  platform: PlatformClient;
  gate?: CaddySwitch;
  status: PaymentStatus;
  graceSec: number;
  save: () => Promise<void>;
  log: Logger;
  /** Receives the onchain per-payment cap at every settlement (the ledger cuts reports at it). */
  onPerPaymentCap?: (cap: bigint) => void;
  /** Records what each payment took from the spend limit (D-048). */
  spend?: SpendRecorder;
  /**
   * What fee settlement may still take from the spend limit, when the agent and not the chain enforces the limit
   * (enclave-account mode, review I6); undefined when the chain does (access-key mode).
   */
  feeLimit?: (now: number) => bigint | undefined;
  /**
   * Rebuilds the ledger from the platform's stored reports (D-062), before anything is cut or paid. Resolves to
   * whether the read succeeded; the ledger says whether this boot was rebuilt at all.
   */
  rebuild?: () => Promise<boolean>;
}

/** Content-free reasons a leg cannot be paid as things stand; they are left out of reserved_for_fees (review L2). */
export type UnpayableReason = "over_payment_cap" | "leg_token_mismatch" | "not_in_deployment";

/** The platform's answer to a report whose period overlaps a stored one (API_CONTRACT 15, D-062). */
function overlapConflict(err: unknown): { usageHash?: string } | undefined {
  if (!(err instanceof HttpError) || err.status !== 409) return undefined;
  const body = err.json() as { error?: { code?: unknown; detail?: { usageHash?: unknown } } } | undefined;
  if (body?.error?.code !== "conflict") return undefined;
  const h = body.error.detail?.usageHash;
  return typeof h === "string" ? { usageHash: h.toLowerCase() } : {};
}

const sumOwed = (es: Due[]) => es.reduce((s, e) => s + e.owed, 0n);
/** Content-free failure code for a budget that cannot cover the next leg. */
const shortfall = (b: Budget) => b.problem ?? (b.binding === "spend_limit" ? "spend_limit" : "insufficient_balance");
const asLines = (es: Due[]): PaymentLine[] => es.map((e) => ({ appId: e.appId, amount: e.owed, usageHash: e.usageHash, paid: e.paid }));

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
        const conflict = overlapConflict(err);
        if (conflict) {
          if (conflict.usageHash === r.usageHash.toLowerCase()) {
            this.d.ledger.markSubmitted(r.usageHash);
            n++;
            continue;
          }
          // Its period overlaps a report the platform already stores, signed by this enclave signer (another copy
          // of this disk, or a state from before a rollback that the rebuild has not seen): billing it would bill
          // that period twice. The next rebuild adopts the stored report.
          this.d.ledger.voidReport(r.usageHash);
          this.d.log.error("the platform already holds a report for this period; this one is void and never paid", { usageHash: r.usageHash, stored: conflict.usageHash });
          continue;
        }
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

  private async payApps(now: number, payable: UnpaidEntry[]): Promise<AppOutcome[]> {
    const { ledger, payer, log } = this.d;
    const outcomes: AppOutcome[] = [];
    const cap = await payer.perPaymentCap();
    this.d.onPerPaymentCap?.(cap);
    let daily = await payer.dailyRemaining();
    let overCap = 0;
    const unpayable: Record<string, UnpayableReason> = {};
    for (const [app, all] of this.byApp(payable)) {
      const due: Due[] = [];
      let appOverCap = 0;
      let mismatched = 0;
      for (const e of all) {
        const paid = await payer.paidAmount(e.usageHash, e.appId);
        if (paid >= e.fee) {
          ledger.markPaid(e.usageHash, app, undefined, now);
          continue;
        }
        if (e.fee > cap) {
          appOverCap++;
          unpayable[`${e.usageHash}:${app}`] = "over_payment_cap";
          continue;
        }
        if (paid > 0n) {
          if ((await payer.legToken(e.usageHash, e.appId)) !== payer.feeToken) {
            mismatched++;
            unpayable[`${e.usageHash}:${app}`] = "leg_token_mismatch";
            continue;
          }
          log.warn("usage paid short onchain, topping up to the report's fee", { app, usageHash: e.usageHash, paid: paid.toString(), fee: e.fee.toString() });
        }
        due.push({ ...e, paid, owed: e.fee - paid });
      }
      overCap += appOverCap;
      if (appOverCap > 0) {
        log.warn("legs above the onchain per-payment cap cannot be paid", { app, legs: appOverCap, cap: cap.toString() });
        outcomes.push({ app, result: "deferred", reason: "over_payment_cap" });
      }
      if (mismatched > 0) {
        log.warn("legs opened in another token cannot be topped up", { app, legs: mismatched });
        outcomes.push({ app, result: "failed", reason: "leg_token_mismatch" });
      }
      if (due.length === 0) continue;
      if (!(await payer.appInDeployment((due[0] as Due).appId))) {
        for (const e of due) unpayable[`${e.usageHash}:${app}`] = "not_in_deployment";
        outcomes.push({ app, result: "failed", reason: "not_in_deployment" });
        continue;
      }
      try {
        const o = await this.payApp(app, due, daily, now);
        if (o.result === "paid") daily -= o.amount;
        outcomes.push(o);
      } catch (err) {
        log.warn("fee payment failed", { app, ...errorFields(err), ...(err instanceof PaymentError ? { outcome: err.outcome, txHash: err.txHash } : {}) });
        outcomes.push({ app, result: "failed", reason: err instanceof PaymentError && err.outcome === "unknown" ? "tx_unconfirmed" : "tx_failed" });
      }
    }
    this.d.status.overCap = overCap;
    this.d.status.unpayable = unpayable;
    return outcomes;
  }

  /** The payer's budget, capped by what the agent's own spend limit leaves for fees (enclave-account mode, review I6). */
  private async budget(reserve: bigint, now: number): Promise<Budget> {
    const b = await this.d.payer.budget(reserve);
    const limit = this.d.feeLimit?.(now);
    if (limit === undefined) return b;
    const left = limit - reserve;
    if (left >= b.spendable) return b;
    return left > 0n ? { spendable: left, binding: "spend_limit" } : { spendable: 0n, problem: "spend_limit", binding: "spend_limit" };
  }

  /**
   * Picks the oldest legs that fit the daily cap and the payer's balance and limit, then estimates the
   * network fee for exactly that batch, shrinking it while the estimate reverts or the fee does not fit.
   */
  private async payApp(app: string, due: Due[], daily: bigint, now: number): Promise<AppOutcome> {
    const { ledger, payer, log } = this.d;
    const raw = await this.budget(0n, now);
    const limit = raw.spendable < daily ? raw.spendable : daily;
    let chosen: Due[] = [];
    let sum = 0n;
    for (const e of due) {
      if (chosen.length >= MAX_LINES_PER_TX || sum + e.owed > limit) break;
      chosen.push(e);
      sum += e.owed;
    }
    const first = (due[0] as Due).owed;
    if (chosen.length === 0) {
      if (daily < first && raw.spendable >= first) return { app, result: "deferred", reason: "daily_cap" };
      return { app, result: "failed", reason: shortfall(raw) };
    }
    let reserve = 0n;
    for (;;) {
      try {
        reserve = await payer.feeReserve(asLines(chosen));
      } catch (err) {
        if (chosen.length === 1) {
          log.warn("payment estimate reverted", { app, usageHash: (chosen[0] as Due).usageHash, ...errorFields(err) });
          return { app, result: "failed", reason: "estimate_reverted" };
        }
        chosen = chosen.slice(0, Math.ceil(chosen.length / 2));
        continue;
      }
      if (sumOwed(chosen) + reserve <= raw.spendable) break;
      if (chosen.length === 1) {
        return { app, result: "failed", reason: shortfall(await this.budget(reserve, now)) };
      }
      chosen = chosen.slice(0, -1);
    }
    sum = sumOwed(chosen);
    let paid: Awaited<ReturnType<FeePayer["pay"]>>;
    try {
      paid = await payer.pay(asLines(chosen));
    } catch (err) {
      // Mined and reverted: the network fee left the limit. Maybe sent: count all it could take until its receipt shows.
      if (err instanceof PaymentError && err.outcome === "reverted") this.d.spend?.recordFees(err.networkFee ?? 0n, now, err.networkFee);
      if (err instanceof PaymentError && err.outcome === "unknown" && err.txHash) this.d.spend?.recordPendingFee(err.txHash, sum, sum + reserve, now);
      if (err instanceof PaymentError && err.outcome !== "not_sent") await this.saveNow();
      throw err;
    }
    const { txHash, gasUsed, networkFee } = paid;
    for (const e of chosen) ledger.markPaid(e.usageHash, app, txHash, now);
    this.d.spend?.recordFees(sum + (networkFee ?? 0n), now, networkFee);
    // On disk before the next app's transaction: a restart must not forget what this one took from the limit.
    await this.saveNow();
    const topUps = chosen.filter((e) => e.paid > 0n).length;
    log.info("fees paid", { app, amount: sum.toString(), reports: chosen.length, topUps, txHash, gasUsed, mode: payer.mode });
    return { app, result: "paid", txHash, amount: sum, reports: chosen.length };
  }

  private async saveNow(): Promise<void> {
    await this.d.save().catch((err) => this.d.log.error("state save failed", errorFields(err)));
  }

  /** Looks up the receipts of payments whose outcome was unknown and corrects what was counted for them. */
  private async reconcilePending(now: number): Promise<void> {
    const { spend, payer, log } = this.d;
    if (!spend) return;
    for (const p of spend.pendingFees()) {
      try {
        const r = payer.paymentReceipt ? await payer.paymentReceipt(p.txHash as Hex) : undefined;
        if (r) {
          const actual = (r.status === "success" ? BigInt(p.owed) : 0n) + r.networkFee;
          spend.resolvePendingFee(p.txHash, actual, now);
          log.info("payment receipt found", { txHash: p.txHash, status: r.status, counted: p.counted, actual: actual.toString() });
        } else if (now - p.at >= PENDING_GIVE_UP_SEC) {
          spend.resolvePendingFee(p.txHash, BigInt(p.counted), now);
          log.warn("no receipt for a payment transaction; it stays counted against the spend limit", { txHash: p.txHash });
        }
      } catch (err) {
        log.warn("could not read a payment receipt", { txHash: p.txHash, ...errorFields(err) });
      }
    }
  }

  async tick(now: number): Promise<SettlementResult> {
    const { ledger, status, log, payer } = this.d;
    await this.reconcilePending(now);
    if (this.d.rebuild) await this.d.rebuild();
    let reportCut = false;
    if (ledger.verified) {
      reportCut = (await ledger.closePeriod(now)) !== undefined;
      // On disk before it leaves the VM: a restart must not cut the same usage again.
      if (reportCut) await this.saveNow();
    }
    const submitted = await this.submitReports();
    const unpaid = ledger.unpaid();
    const waiting = unpaid.filter((e) => !e.submitted);
    let deployment: DeploymentStatus | "unknown";
    try {
      deployment = await payer.deploymentStatus();
    } catch (err) {
      log.warn("chain read failed", errorFields(err));
      deployment = "unknown";
    }
    let apps: AppOutcome[] = [];
    let outcome: SettlementResult["outcome"];
    if (deployment === "closed") outcome = "deployment_closed";
    else if (!ledger.verified) {
      outcome = "failed";
      apps = [{ app: "*", result: "failed", reason: "ledger_unverified" }];
    } else if (unpaid.length === 0) outcome = "nothing_due";
    else if (deployment === "unknown") {
      outcome = "failed";
      apps = [{ app: "*", result: "failed", reason: "rpc_error" }];
    } else if (deployment === "none") outcome = "deployment_not_registered";
    else {
      try {
        apps = await this.payApps(now, unpaid.filter((e) => e.submitted));
      } catch (err) {
        log.warn("settlement failed", errorFields(err));
        apps = [{ app: "*", result: "failed", reason: "rpc_error" }];
      }
      // Paid only once the platform holds them (D-062): waiting reports keep billing failing until they are in.
      if (waiting.length > 0) apps.push({ app: "*", result: "failed", reason: "usage_not_submitted" });
      const failed = apps.some((a) => a.result === "failed");
      const paid = apps.some((a) => a.result === "paid");
      outcome = failed ? (paid ? "partial" : "failed") : "settled";
    }
    status.lastAttemptAt = now;
    status.lastOutcome = apps.find((a) => a.result === "failed")?.reason ?? outcome;
    if (outcome === "deployment_closed") status.failingSince ??= now;
    else if (outcome === "deployment_not_registered") {
      const oldest = Math.min(...unpaid.map((e) => e.createdAt));
      status.failingSince = status.failingSince === null ? oldest : Math.min(status.failingSince, oldest);
    } else if (apps.some((a) => a.result === "failed")) {
      // Measured from the oldest report the platform has not accepted, so blocking the platform API does not help.
      const since = waiting.length > 0 ? Math.min(now, ...waiting.map((e) => e.createdAt)) : now;
      status.failingSince = status.failingSince === null ? since : Math.min(status.failingSince, since);
    } else status.failingSince = null;
    if (apps.some((a) => a.result === "paid")) status.lastPaidAt = now;
    await this.updateGate(now, outcome === "deployment_closed", ledger.unpaid().length === 0 || apps.some((a) => a.result === "paid"));
    await this.d.save();
    return { at: now, reportCut, submitted, outcome, apps, paymentNeeded: status.paymentNeeded };
  }

  private async updateGate(now: number, closed: boolean, recovered: boolean): Promise<void> {
    const { status, gate, log } = this.d;
    try {
      if (closed || (status.failingSince !== null && now - status.failingSince >= this.d.graceSec)) {
        if (!status.paymentNeeded) {
          log.warn(closed ? "deployment is closed onchain, switching to the payment-needed page" : "payments failing beyond the grace period, switching to the payment-needed page", {
            failingSince: status.failingSince,
          });
        }
        status.paymentNeeded = true;
        await gate?.apply("payment-needed");
      } else if (status.paymentNeeded && status.failingSince === null && recovered) {
        await gate?.apply("normal");
        status.paymentNeeded = false;
        log.info("payment succeeded, app routes restored");
      } else if (status.paymentNeeded) {
        // Re-applied every tick: Caddy restarts from the normal Caddyfile.
        await gate?.apply("payment-needed");
      }
    } catch (err) {
      log.error("could not update Caddy routes", errorFields(err));
    }
  }
}
