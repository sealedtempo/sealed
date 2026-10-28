// Per-app, per-period usage aggregation (spec 7.1). Usage is priced as it arrives so no report item
// ever exceeds the FeeSplitter per-payment cap: when an app would cross it, the period is cut and
// the rest of the usage goes into the next one. Each closed period becomes one EIP-712 UsageReport
// signed by the enclave signer; its digest is the usageHash for every app's payment.
import {
  appId as computeAppId,
  type Eip712Domain,
  type FeeSchedule,
  type Hex,
  priceQuantity,
  priceRuleFor,
  maxQuantityWithinFee,
  signUsageReport,
  type UsageItem,
  UsageUnit,
  type UsageUnitName,
  usageReportDigest,
  usageReportToJson,
  type UsageReport,
  type UsageReportJson,
} from "@sealed/core";

export const UNITS: UsageUnitName[] = ["tokens", "pages", "app_hour"];

export interface AppPayment {
  appId: Hex;
  fee: string;
  status: "unpaid" | "paid";
  txHash?: Hex;
  paidAt?: number;
}

export interface StoredReport {
  report: UsageReportJson;
  signature: Hex;
  usageHash: Hex;
  createdAt: number;
  submitted: boolean;
  payments: Record<string, AppPayment>;
}

export interface LedgerState {
  periodStart: number;
  /** app -> unit -> quantity (decimal string) in the open period */
  open: Record<string, Partial<Record<UsageUnitName, string>>>;
  /** "app:unit" -> pricing remainder carried into the open period */
  carry: Record<string, string>;
  reports: StoredReport[];
  recentEventIds: string[];
}

export function emptyLedgerState(now: number): LedgerState {
  return { periodStart: now, open: {}, carry: {}, reports: [], recentEventIds: [] };
}

export interface LedgerDeps {
  deploymentId: Hex;
  /** Allowed app slugs in report order (config order, sorted by id). */
  apps: string[];
  schedule: FeeSchedule;
  domain: Eip712Domain;
  enclaveKey: Hex;
  perPaymentCap: () => bigint;
  onChange?: () => void;
}

export interface UnpaidEntry {
  usageHash: Hex;
  app: string;
  appId: Hex;
  fee: bigint;
  createdAt: number;
}

const MAX_EVENT_IDS = 5000;
/** One usage event may cut at most this many reports (each fits one payFees call). */
export const MAX_CUTS_PER_EVENT = 8;

export class TooManyReportsError extends Error {}
const KEEP_SETTLED_REPORTS = 50;

export class Ledger {
  private readonly appIds: Map<string, Hex>;
  constructor(
    readonly state: LedgerState,
    private readonly deps: LedgerDeps,
  ) {
    this.appIds = new Map(deps.apps.map((a) => [a, computeAppId(a)]));
  }

  hasApp(app: string): boolean {
    return this.appIds.has(app);
  }

  /** True if this idempotency key was seen recently; records it otherwise. */
  seen(eventId: string): boolean {
    if (this.state.recentEventIds.includes(eventId)) return true;
    this.state.recentEventIds.push(eventId);
    if (this.state.recentEventIds.length > MAX_EVENT_IDS) this.state.recentEventIds.splice(0, this.state.recentEventIds.length - MAX_EVENT_IDS);
    return false;
  }

  private qty(app: string, unit: UsageUnitName, open = this.state.open): bigint {
    return BigInt(open[app]?.[unit] ?? "0");
  }

  private carryOf(app: string, unit: UsageUnitName): bigint {
    return BigInt(this.state.carry[`${app}:${unit}`] ?? "0");
  }

  private unitFee(app: string, unit: UsageUnitName, quantity = this.qty(app, unit)): bigint {
    return priceQuantity(quantity, priceRuleFor(this.deps.schedule, app, unit), this.carryOf(app, unit)).fee;
  }

  /** Fee the open period currently owes for an app, across units. */
  openFee(app: string): bigint {
    return UNITS.reduce((sum, u) => sum + this.unitFee(app, u), 0n);
  }

  /**
   * Adds usage. Returns the reports that had to be cut because an app reached the per-payment cap.
   * Rejects (recording nothing) an event that would cut more than `MAX_CUTS_PER_EVENT` reports.
   */
  async record(app: string, unit: UsageUnitName, quantity: bigint, now: number): Promise<StoredReport[]> {
    if (!this.hasApp(app)) throw new Error(`unknown app ${app}`);
    if (quantity < 0n) throw new Error("negative quantity");
    const rule = priceRuleFor(this.deps.schedule, app, unit);
    const cap0 = this.deps.perPaymentCap();
    if (cap0 > 0n && priceQuantity(quantity, rule, 0n).fee > cap0 * BigInt(MAX_CUTS_PER_EVENT)) {
      throw new TooManyReportsError(`one ${unit} event of ${quantity} would cut more than ${MAX_CUTS_PER_EVENT} reports`);
    }
    const cut: StoredReport[] = [];
    let remaining = quantity;
    for (let rounds = 0; remaining > 0n; rounds++) {
      if (rounds > MAX_CUTS_PER_EVENT + 2) throw new TooManyReportsError("usage does not fit the per-payment cap");
      const cap = this.deps.perPaymentCap();
      const current = this.qty(app, unit);
      const otherFees = this.openFee(app) - this.unitFee(app, unit);
      const maxTotal = maxQuantityWithinFee(rule, this.carryOf(app, unit), cap - otherFees);
      const room = maxTotal === null ? remaining : maxTotal - current;
      if (room >= remaining || (room <= 0n && this.isOpenEmpty())) {
        // Fits, or a single unit already costs more than the cap: nothing smaller can be split off.
        this.setQty(app, unit, current + remaining);
        remaining = 0n;
        break;
      }
      if (room > 0n) {
        this.setQty(app, unit, current + room);
        remaining -= room;
      }
      const report = await this.closePeriod(now);
      if (report) cut.push(report);
    }
    this.deps.onChange?.();
    return cut;
  }

  private setQty(app: string, unit: UsageUnitName, q: bigint): void {
    this.state.open[app] ??= {};
    (this.state.open[app] as Partial<Record<UsageUnitName, string>>)[unit] = q.toString();
  }

  private isOpenEmpty(open = this.state.open): boolean {
    return Object.values(open).every((units) => Object.values(units).every((q) => !q || q === "0"));
  }

  /**
   * Closes the open period into a signed report. Returns undefined when nothing was used. The open
   * quantities are taken and the next period started before signing, so usage recorded while the
   * signature is computed lands in the next period instead of being lost.
   */
  async closePeriod(now: number): Promise<StoredReport | undefined> {
    const open = this.state.open;
    if (this.isOpenEmpty(open)) return undefined;
    const periodStart = this.state.periodStart;
    const periodEnd = Math.max(now, periodStart + 1);
    const items: UsageItem[] = [];
    const payments: Record<string, AppPayment> = {};
    const carryBefore: Record<string, string | undefined> = {};
    for (const app of this.deps.apps) {
      const appId = this.appIds.get(app) as Hex;
      let appFee = 0n;
      for (const unit of UNITS) {
        const q = this.qty(app, unit, open);
        if (q === 0n) continue;
        const key = `${app}:${unit}`;
        const priced = priceQuantity(q, priceRuleFor(this.deps.schedule, app, unit), this.carryOf(app, unit));
        carryBefore[key] = this.state.carry[key];
        this.state.carry[key] = priced.carry.toString();
        items.push({ appId, unit: UsageUnit[unit], quantity: q, fee: priced.fee });
        appFee += priced.fee;
      }
      if (appFee > 0n) payments[app] = { appId, fee: appFee.toString(), status: "unpaid" };
    }
    this.state.open = {};
    this.state.periodStart = periodEnd;
    const report: UsageReport = { deploymentId: this.deps.deploymentId, periodStart: BigInt(periodStart), periodEnd: BigInt(periodEnd), items };
    let signature: Hex;
    try {
      signature = await signUsageReport(report, this.deps.domain, this.deps.enclaveKey);
    } catch (err) {
      // Put the usage back into the open period.
      for (const [app, units] of Object.entries(open)) {
        for (const [unit, q] of Object.entries(units)) this.setQty(app, unit as UsageUnitName, this.qty(app, unit as UsageUnitName) + BigInt(q ?? "0"));
      }
      for (const [key, v] of Object.entries(carryBefore)) {
        if (v === undefined) delete this.state.carry[key];
        else this.state.carry[key] = v;
      }
      this.state.periodStart = Math.min(this.state.periodStart, periodStart);
      throw err;
    }
    const stored: StoredReport = {
      report: usageReportToJson(report),
      signature,
      usageHash: usageReportDigest(report, this.deps.domain),
      createdAt: now,
      submitted: false,
      payments,
    };
    this.state.reports.push(stored);
    this.prune();
    this.deps.onChange?.();
    return stored;
  }

  /** Unpaid (report, app) pairs, oldest first. */
  unpaid(): UnpaidEntry[] {
    const out: UnpaidEntry[] = [];
    for (const r of this.state.reports) {
      for (const [app, p] of Object.entries(r.payments)) {
        if (p.status === "unpaid") out.push({ usageHash: r.usageHash, app, appId: p.appId, fee: BigInt(p.fee), createdAt: r.createdAt });
      }
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  markPaid(usageHash: Hex, app: string, txHash: Hex | undefined, at: number): void {
    const r = this.state.reports.find((x) => x.usageHash === usageHash);
    const p = r?.payments[app];
    if (!p) return;
    p.status = "paid";
    p.txHash = txHash;
    p.paidAt = at;
    this.prune();
    this.deps.onChange?.();
  }

  unsubmitted(): StoredReport[] {
    return this.state.reports.filter((r) => !r.submitted);
  }

  markSubmitted(usageHash: Hex): void {
    const r = this.state.reports.find((x) => x.usageHash === usageHash);
    if (r) r.submitted = true;
    this.prune();
    this.deps.onChange?.();
  }

  totals(): { metered: bigint; unpaid: bigint } {
    let metered = 0n;
    let unpaid = 0n;
    for (const r of this.state.reports) {
      for (const p of Object.values(r.payments)) {
        metered += BigInt(p.fee);
        if (p.status === "unpaid") unpaid += BigInt(p.fee);
      }
    }
    return { metered, unpaid };
  }

  /** Drops old reports that are submitted and fully paid. */
  private prune(): void {
    const settled = (r: StoredReport) => r.submitted && Object.values(r.payments).every((p) => p.status === "paid");
    const excess = this.state.reports.filter(settled).length - KEEP_SETTLED_REPORTS;
    if (excess <= 0) return;
    let dropped = 0;
    this.state.reports = this.state.reports.filter((r) => !(settled(r) && dropped++ < excess));
  }
}
