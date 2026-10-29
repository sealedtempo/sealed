// Settlement (spec 5.6 steps 6-8, 7.3): every interval, close the usage period, submit signed
// reports, and pay each app's unpaid reports in one transaction within the FeeSplitter daily cap
// and the payer's budget. A (report, app) leg is settled only when FeeSplitter's usagePaid reaches
// the report's fee: a leg paid short (the customer can pay first with any amount) is topped up with
// the shortfall, so it is never settled for less.
//
// Billing fails closed on the customer's side, and only failures there count toward the grace period
// (D-048, D-073): a missing, revoked or expired access key, an exhausted limit, too little balance
// (also when it covers only part of what is due), a reverted estimate or transaction, a leg that cannot
// be topped up, and a chain read error (the customer chooses the RPC and controls the VPC firewall, so
// it can block the RPC). Failures that last the grace period switch Caddy to the measured
// payment-needed Caddyfile; a Closed deployment (terminal) switches at once. A failure streak ends, and
// the normal Caddyfile comes back, only once no leg that was due at the previous settlement is left
// unpaid: paying part of a backlog is outcome `partial`, not a recovery, so a limit below the fees
// cannot restart the grace period at every limit period while the debt grows. Limits the operator sets
// onchain are deferrals, not failures: the daily cap, and legs above a lowered per-payment cap
// (reported as overCap, never paid at that cap).
//
// D-073: a platform outage never puts a customer on the payment-needed page. What only the platform or
// the operator can do defers settlement instead: rebuilding this boot's ledger from its stored reports,
// accepting a report, registering the deployment (the oracle and the ops key do, from the agent's
// evidence), and a FeeSplitter the operator paused. While nothing but those fails, settlement records
// deferredSince and the grace period does not run: none starts, and one a customer-side failure started
// stands still until settlement resumes. Deferred fees are paid once the platform is back. A tick that
// pays every leg it can try and leaves none overdue shows the customer's side works, so it ends a
// customer-side failure streak even during a deferral.
//
// D-062: a report is paid only once the platform has accepted it, so every paid period is among the
// stored reports the agent rebuilds its ledger from after a disk rollback. Each tick first rebuilds
// (the agent reads the platform's stored reports), cuts nothing while this boot's ledger is not yet
// rebuilt, saves a cut report before it leaves the VM, and voids a report the platform refuses as
// overlapping a stored one. Reports the platform has accepted are paid even while it is unreachable.
import type { Hex } from "@sealed/core";
import type { CaddySwitch } from "../caddy.js";
import type { PlatformClient } from "../evidence.js";
import { HttpError } from "../http.js";
import { errorFields, type Logger } from "../log.js";
import type { Ledger, UnpaidEntry } from "../metering/ledger.js";
import type { PaymentStatus } from "../state.js";
import { type Budget, type DeploymentStatus, type FeePayer, isEnforcedPause, MAX_LINES_PER_TX, PaymentError, type PaymentLine } from "./feePayer.js";

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

/**
 * Failures on the platform's side (D-073): the platform api's stored reports could not be read (D-062), it has not
 * accepted a report yet, it has not registered the deployment onchain (the oracle registers it from the agent's
 * evidence, which an unreachable api never gets), or the operator paused FeeSplitter (payFees and topUpFees revert
 * EnforcedPause). Settlement is deferred and the grace period does not run; only failures on the customer's side
 * (key, limit, balance, a reverted payment, the customer's RPC) count toward it.
 */
export const PLATFORM_SIDE_FAILURES: ReadonlySet<string> = new Set(["ledger_unverified", "usage_not_submitted", "deployment_not_registered", "fee_splitter_paused"]);

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
  /** FeeSplitter.paused() as read in this settlement, after a revert (payments-4). */
  private pausedRead: Promise<boolean> | undefined;

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
    this.pausedRead = undefined;
    const cap = await payer.perPaymentCap();
    this.d.onPerPaymentCap?.(cap);
    let daily = await payer.dailyRemaining();
    let overCap = 0;
    const unpayable: Record<string, UnpayableReason> = {};
    for (const [app, all] of this.byApp(payable)) {
      const due: Due[] = [];
      // One transaction pays at most MAX_LINES_PER_TX legs, so the legs behind them wait for a later settlement
      // without a usagePaid read now: a long backlog costs no chain read per leg at every settlement.
      const later: UnpaidEntry[] = [];
      let appOverCap = 0;
      let mismatched = 0;
      for (const e of all) {
        if (due.length >= MAX_LINES_PER_TX && e.fee <= cap) {
          later.push(e);
          continue;
        }
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
        for (const e of [...due, ...later]) unpayable[`${e.usageHash}:${app}`] = "not_in_deployment";
        outcomes.push({ app, result: "failed", reason: "not_in_deployment" });
        continue;
      }
      try {
        for (const o of await this.payApp(app, due, daily, now)) {
          if (o.result === "paid") daily -= o.amount;
          outcomes.push(o);
        }
      } catch (err) {
        log.warn("fee payment failed", { app, ...errorFields(err), ...(err instanceof PaymentError ? { outcome: err.outcome, txHash: err.txHash } : {}) });
        const unknown = err instanceof PaymentError && err.outcome === "unknown";
        outcomes.push({ app, result: "failed", reason: unknown ? "tx_unconfirmed" : (await this.splitterPaused(err)) ? "fee_splitter_paused" : "tx_failed" });
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
   * Whether the operator paused FeeSplitter (payments-4): the revert decodes as EnforcedPause, or paused() reads true.
   * paused() is read at most once per settlement, and only after something reverted.
   */
  private async splitterPaused(err: unknown): Promise<boolean> {
    if (isEnforcedPause(err)) return true;
    const read = this.d.payer.splitterPaused;
    if (!read) return false;
    this.pausedRead ??= read.call(this.d.payer).catch(() => false);
    return this.pausedRead;
  }

  /**
   * Picks the oldest legs that fit the daily cap and the payer's balance and limit, then estimates the
   * network fee for exactly that batch, shrinking it while the estimate reverts or the fee does not fit.
   * A leg the budget leaves behind adds the shortfall as a failure (the customer's side), one the daily cap
   * leaves behind a daily_cap deferral; legs left only because one transaction holds at most MAX_LINES_PER_TX
   * wait for the next settlement (tick counts them as overdue, so they keep a failure streak running).
   */
  private async payApp(app: string, due: Due[], daily: bigint, now: number): Promise<AppOutcome[]> {
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
    const next = chosen.length < MAX_LINES_PER_TX ? due[chosen.length] : undefined;
    let left: AppOutcome | undefined =
      next === undefined ? undefined : sum + next.owed > raw.spendable ? { app, result: "failed", reason: shortfall(raw) } : { app, result: "deferred", reason: "daily_cap" };
    if (chosen.length === 0) return [left as AppOutcome];
    let reserve = 0n;
    for (;;) {
      try {
        reserve = await payer.feeReserve(asLines(chosen));
      } catch (err) {
        if (await this.splitterPaused(err)) {
          // D-073: the operator's pause, not the customer's failure. A budget shortfall still counts.
          log.warn("FeeSplitter is paused; settlement is deferred until the operator unpauses it", { app, ...errorFields(err) });
          const paused: AppOutcome = { app, result: "failed", reason: "fee_splitter_paused" };
          return left?.result === "failed" ? [left, paused] : [paused];
        }
        if (chosen.length === 1) {
          log.warn("payment estimate reverted", { app, usageHash: (chosen[0] as Due).usageHash, ...errorFields(err) });
          return [{ app, result: "failed", reason: "estimate_reverted" }];
        }
        chosen = chosen.slice(0, Math.ceil(chosen.length / 2));
        continue;
      }
      if (sumOwed(chosen) + reserve <= raw.spendable) break;
      if (chosen.length === 1) {
        return [{ app, result: "failed", reason: shortfall(await this.budget(reserve, now)) }];
      }
      chosen = chosen.slice(0, -1);
      // The network fee does not fit on top of every chosen leg: the budget leaves the last one behind.
      left = { app, result: "failed", reason: shortfall(raw) };
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
    const paidOutcome: AppOutcome = { app, result: "paid", txHash, amount: sum, reports: chosen.length };
    if (left?.result === "failed") log.warn("the budget covers only part of the fees due", { app, reason: left.reason, left: due.length - chosen.length });
    return left ? [paidOutcome, left] : [paidOutcome];
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

  /**
   * Legs the customer is behind on: submitted, payable (not in `unpayable`), cut at or before the previous settlement
   * and still unpaid, in apps that no operator or platform limit held back in this settlement (the daily cap, a
   * paused FeeSplitter). Any of them keeps a failure streak running (payments-3).
   */
  private overdue(apps: AppOutcome[], previous: number | undefined): number {
    if (previous === undefined) return 0;
    const held = new Set(
      apps.filter((a) => (a.result === "deferred" && a.reason === "daily_cap") || (a.result === "failed" && PLATFORM_SIDE_FAILURES.has(a.reason))).map((a) => a.app),
    );
    const unpayable = this.d.status.unpayable ?? {};
    return this.d.ledger.unpaid().filter((e) => e.submitted && e.createdAt <= previous && !held.has(e.app) && !unpayable[`${e.usageHash}:${e.app}`]).length;
  }

  async tick(now: number): Promise<SettlementResult> {
    const { ledger, status, log, payer } = this.d;
    // A leg cut at or before the previous settlement was due then; still unpaid now, it is overdue.
    const previous = status.lastAttemptAt;
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
    let overdue = 0;
    if (deployment === "closed") outcome = "deployment_closed";
    else if (!ledger.verified) {
      outcome = "failed";
      apps = [{ app: "*", result: "failed", reason: "ledger_unverified" }];
    } else if (unpaid.length === 0) outcome = "nothing_due";
    else if (deployment === "unknown") {
      outcome = "failed";
      apps = [{ app: "*", result: "failed", reason: "rpc_error" }];
    } else if (deployment === "none") {
      // Nothing can be paid before the platform registers the deployment (D-073: deferred, the platform's side).
      outcome = "deployment_not_registered";
      apps = [{ app: "*", result: "failed", reason: "deployment_not_registered" }];
    } else {
      try {
        apps = await this.payApps(now, unpaid.filter((e) => e.submitted));
      } catch (err) {
        log.warn("settlement failed", errorFields(err));
        apps = [{ app: "*", result: "failed", reason: "rpc_error" }];
      }
      // Paid only once the platform holds them (D-062): waiting reports defer settlement until they are in (D-073).
      if (waiting.length > 0) apps.push({ app: "*", result: "failed", reason: "usage_not_submitted" });
      overdue = this.overdue(apps, previous);
      const failed = apps.some((a) => a.result === "failed");
      const paid = apps.some((a) => a.result === "paid");
      outcome = failed ? (paid ? "partial" : "failed") : overdue > 0 ? "partial" : "settled";
    }
    status.lastAttemptAt = now;
    status.lastOutcome = apps.find((a) => a.result === "failed")?.reason ?? outcome;
    const failures = apps.filter((a) => a.result === "failed");
    const customerSide = failures.some((a) => !PLATFORM_SIDE_FAILURES.has(a.reason));
    const paidSome = apps.some((a) => a.result === "paid");
    const deferred = failures.length > 0 && !customerSide && outcome !== "deployment_closed";
    if (deferred) {
      // D-073: a platform outage defers settlement; the grace period is paused, never started by it.
      status.deferredSince ??= now;
      // Every leg the customer's side could be asked to pay was paid and none is overdue: its failure streak is over,
      // so the outage cannot keep a customer who fixed their key, limit or balance on the payment-needed page either.
      if (paidSome && overdue === 0) status.failingSince = null;
    } else {
      this.resumeGrace(now);
      if (outcome === "deployment_closed" || customerSide) status.failingSince ??= now;
      // Part of a backlog paid is no recovery: the streak runs on until no overdue leg is left (payments-3).
      else if (overdue === 0) status.failingSince = null;
    }
    if (paidSome) status.lastPaidAt = now;
    await this.updateGate(now, outcome === "deployment_closed");
    await this.d.save();
    return { at: now, reportCut, submitted, outcome, apps, paymentNeeded: status.paymentNeeded };
  }

  /** Ends a D-073 deferral: the time the platform was unreachable does not count toward the grace period. */
  private resumeGrace(now: number): void {
    const { status } = this.d;
    if (status.deferredSince === undefined) return;
    if (status.failingSince !== null) status.failingSince = Math.min(now, status.failingSince + Math.max(0, now - status.deferredSince));
    delete status.deferredSince;
  }

  private async updateGate(now: number, closed: boolean): Promise<void> {
    const { status, gate, log } = this.d;
    // While deferred (D-073) the grace clock stands still at the deferral's start.
    const clock = status.deferredSince ?? now;
    try {
      if (closed || (status.failingSince !== null && clock - status.failingSince >= this.d.graceSec)) {
        if (!status.paymentNeeded) {
          log.warn(closed ? "deployment is closed onchain, switching to the payment-needed page" : "payments failing beyond the grace period, switching to the payment-needed page", {
            failingSince: status.failingSince,
          });
        }
        status.paymentNeeded = true;
        await gate?.apply("payment-needed");
      } else if (status.paymentNeeded && status.failingSince === null) {
        // failingSince is null only once nothing overdue is left unpaid, not after a partial payment (payments-3).
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
