// Per-app, per-period usage aggregation (spec 7.1). Usage is priced as it arrives so no report item
// ever exceeds the FeeSplitter per-payment cap: when an app would cross it, the period is cut and
// the rest of the usage goes into the next one. Each closed period becomes one EIP-712 UsageReport
// signed by the enclave signer; its digest is the usageHash for every app's payment.
//
// D-062: the host can roll the data disk (and so this state) back to an older copy. FeeSplitter dedupes
// per usageHash only, so usage the rolled-back state still holds as open, cut again into a report with
// another period, would be paid twice. Therefore:
// - `signedThrough` is the end of the latest period signed for this deployment that the agent knows of,
//   and no report is ever signed for a period that starts before it (consecutive periods share a boundary);
// - at boot the agent holds the usage it read from disk (`holdForRebuild`) and cuts nothing until it has
//   adopted the reports the platform stores that verify against its own signer (`adopt`). Usage held from a
//   period that a signed report already passes is covered by that report and is dropped; the rest is kept;
// - a report the platform refuses as overlapping a stored one is void and never paid (`voidReport`).
// Adopted reports carry their payment state from onchain usagePaid, which the settler reads.
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
  /** Read back from the platform's stored reports (D-062), not cut by this copy of the state. */
  adopted?: boolean;
  /** The platform refused it as overlapping a stored report: never paid (D-062). */
  void?: boolean;
}

type OpenUsage = Record<string, Partial<Record<UsageUnitName, string>>>;

/** Usage read from disk at boot, held until a rebuild shows whether a signed report already covers it. */
export interface HeldUsage {
  periodStart: number;
  open: OpenUsage;
}

export interface LedgerState {
  periodStart: number;
  /** app -> unit -> quantity (decimal string) in the open period */
  open: OpenUsage;
  /** "app:unit" -> pricing remainder carried into the open period */
  carry: Record<string, string>;
  reports: StoredReport[];
  recentEventIds: string[];
  /** End of the latest period signed for this deployment that the agent knows of (D-062). */
  signedThrough?: number;
  /** The platform listing's `after` cursor past the last stored report checked (D-062). */
  platformCursor?: string;
  /** Usage from disk waiting for this boot's rebuild (D-062). */
  held?: HeldUsage[];
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
  /** The platform accepted the report: only then may it be paid (D-062). */
  submitted: boolean;
}

/** A stored report from the platform whose signature recovers to this enclave signer. */
export interface VerifiedReport {
  report: UsageReport;
  signature: Hex;
  usageHash: Hex;
  receivedAt: number;
}

export interface AdoptResult {
  /** Reports the local state did not know. */
  adopted: number;
  /** Local reports the platform turned out to hold already (now submitted). */
  confirmed: number;
  /** Held usage entries dropped because a signed report already covers their period. */
  droppedUsage: number;
  /** Held usage entries kept (their period starts at or after every signed report). */
  keptUsage: number;
  signedThrough: number;
}

const MAX_EVENT_IDS = 5000;
/** One usage event may cut at most this many reports (each fits one payFees call). */
export const MAX_CUTS_PER_EVENT = 8;
/**
 * B1 (D-089): the trailing window over which `projectedFee` estimates a callback-metered app's fee-accrual rate,
 * and the bucket width it keeps samples in. feeReserve projects this rate across the rest of the limit window, so a
 * payer that spends its whole share cannot starve settlement on the period tail. The samples are in memory only
 * (they rebuild within one window after a restart); the money invariant is enforced by the chain regardless.
 */
export const ACCRUAL_WINDOW_SEC = 300;
const ACCRUAL_BUCKET_SEC = 5;

export class TooManyReportsError extends Error {}
/** A report would have to be cut before this boot's ledger rebuild (D-062): try again later. */
export class LedgerUnverifiedError extends Error {}
const KEEP_SETTLED_REPORTS = 50;

export class Ledger {
  private readonly appIds: Map<string, Hex>;
  private readonly slugs: Map<string, string>;
  /** False from holdForRebuild until adopt: nothing is cut or signed (D-062). */
  private rebuilt = true;
  /** B1 (D-089): recent fee accrual per app, bucketed by ACCRUAL_BUCKET_SEC, for projectedFee. In memory only. */
  private readonly accrual = new Map<string, Map<number, bigint>>();
  constructor(
    readonly state: LedgerState,
    private readonly deps: LedgerDeps,
  ) {
    this.appIds = new Map(deps.apps.map((a) => [a, computeAppId(a)]));
    this.slugs = new Map(deps.apps.map((a) => [computeAppId(a), a]));
  }

  /** Whether reports may be cut: true unless a boot is still waiting for its ledger rebuild. */
  get verified(): boolean {
    return this.rebuilt;
  }

  /** The end of the latest period known to be signed, from the state and its reports. */
  private knownSignedThrough(): number {
    let end = this.state.signedThrough ?? 0;
    for (const r of this.state.reports) end = Math.max(end, r.report.periodEnd);
    return end;
  }

  /**
   * Boot (D-062): the state just came from a disk the host may have rolled back. The open usage is held, and no
   * report is cut until `adopt` has merged the platform's stored reports. Usage recorded from `now` on is new, so
   * it starts its own period at `now`: a rebuild that drops the held usage keeps it.
   */
  holdForRebuild(now?: number): void {
    this.rebuilt = false;
    if (!this.isOpenEmpty()) {
      this.state.held = [...(this.state.held ?? []), { periodStart: this.state.periodStart, open: this.state.open }];
      this.state.open = {};
      if (now !== undefined) this.state.periodStart = Math.max(this.state.periodStart, now);
    }
    this.deps.onChange?.();
  }

  /**
   * Merges stored reports that verify against this enclave signer (D-062). Unknown ones join the ledger as
   * submitted, unpaid until the settler finds usagePaid onchain; known ones are marked submitted. Then held
   * usage from a period a signed report already passes is dropped, the rest goes back into the open period,
   * and the open period starts no earlier than the last signed period ends.
   */
  adopt(reports: VerifiedReport[], cursor?: string): AdoptResult {
    const result: AdoptResult = { adopted: 0, confirmed: 0, droppedUsage: 0, keptUsage: 0, signedThrough: 0 };
    const known = new Map(this.state.reports.map((r) => [r.usageHash.toLowerCase(), r]));
    for (const v of reports) {
      if (v.report.deploymentId.toLowerCase() !== this.deps.deploymentId.toLowerCase()) continue;
      const hash = v.usageHash.toLowerCase() as Hex;
      const local = known.get(hash);
      if (local) {
        if (!local.submitted) {
          local.submitted = true;
          result.confirmed++;
        }
        continue;
      }
      const payments: Record<string, AppPayment> = {};
      for (const item of v.report.items) {
        const app = this.slugs.get(item.appId.toLowerCase());
        if (!app || item.fee === 0n) continue;
        const prev = payments[app];
        payments[app] = { appId: item.appId.toLowerCase() as Hex, fee: ((prev ? BigInt(prev.fee) : 0n) + item.fee).toString(), status: "unpaid" };
      }
      const stored: StoredReport = {
        report: usageReportToJson(v.report),
        signature: v.signature,
        usageHash: hash,
        createdAt: Number(v.report.periodEnd),
        submitted: true,
        payments,
        adopted: true,
      };
      this.state.reports.push(stored);
      known.set(hash, stored);
      result.adopted++;
    }
    this.state.reports.sort((a, b) => a.report.periodEnd - b.report.periodEnd || a.createdAt - b.createdAt);
    const through = this.knownSignedThrough();
    this.state.signedThrough = through;
    result.signedThrough = through;
    if (cursor !== undefined) this.state.platformCursor = cursor;
    for (const h of this.state.held ?? []) {
      if (h.periodStart < through) {
        result.droppedUsage += Object.values(h.open).reduce((n, units) => n + Object.keys(units).length, 0);
        continue;
      }
      for (const [app, units] of Object.entries(h.open)) {
        if (!this.hasApp(app)) continue;
        for (const [unit, q] of Object.entries(units)) {
          this.setQty(app, unit as UsageUnitName, this.qty(app, unit as UsageUnitName) + BigInt(q ?? "0"));
          result.keptUsage++;
        }
      }
      this.state.periodStart = Math.min(this.state.periodStart, h.periodStart);
    }
    delete this.state.held;
    this.state.periodStart = Math.max(this.state.periodStart, through);
    this.rebuilt = true;
    this.prune();
    this.deps.onChange?.();
    return result;
  }

  /** The platform refused this report as overlapping a stored one (D-062): it is never paid. */
  voidReport(usageHash: Hex): void {
    const r = this.state.reports.find((x) => x.usageHash.toLowerCase() === usageHash.toLowerCase());
    if (!r || r.void) return;
    r.void = true;
    this.prune();
    this.deps.onChange?.();
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
   * Throws exactly what `record` would reject this event with before it mutates anything (unknown app, negative
   * quantity, an event too large for the per-payment cap). B2 (D-089): recordUsage calls it before write-ahead, so
   * an event it will reject is never journaled.
   */
  checkAcceptable(app: string, unit: UsageUnitName, quantity: bigint): void {
    if (!this.hasApp(app)) throw new Error(`unknown app ${app}`);
    if (quantity < 0n) throw new Error("negative quantity");
    const rule = priceRuleFor(this.deps.schedule, app, unit);
    const cap0 = this.deps.perPaymentCap();
    if (cap0 > 0n && priceQuantity(quantity, rule, 0n).fee > cap0 * BigInt(MAX_CUTS_PER_EVENT)) {
      throw new TooManyReportsError(`one ${unit} event of ${quantity} would cut more than ${MAX_CUTS_PER_EVENT} reports`);
    }
  }

  /**
   * B2 (D-089): adds write-ahead-journal usage straight into the open period at boot, without cutting or signing, so
   * holdForRebuild sweeps it into `held` and adopt reconciles it against the platform's signed reports like any other
   * disk-resident open usage (D-062). Not for live usage; use `record` for that.
   */
  restoreOpen(app: string, unit: UsageUnitName, quantity: bigint): void {
    if (!this.hasApp(app) || quantity <= 0n) return;
    this.setQty(app, unit, this.qty(app, unit) + quantity);
    this.deps.onChange?.();
  }

  /** B1 (D-089): records a fee increment in the trailing accrual window and drops samples older than it. */
  private noteAccrual(app: string, fee: bigint, now: number): void {
    if (fee <= 0n) return;
    let buckets = this.accrual.get(app);
    if (!buckets) {
      buckets = new Map();
      this.accrual.set(app, buckets);
    }
    const bucket = Math.floor(now / ACCRUAL_BUCKET_SEC) * ACCRUAL_BUCKET_SEC;
    buckets.set(bucket, (buckets.get(bucket) ?? 0n) + fee);
    const oldest = now - ACCRUAL_WINDOW_SEC;
    for (const b of buckets.keys()) if (b < oldest) buckets.delete(b);
  }

  /**
   * B1 (D-089): the fee this app is estimated to accrue over `horizonSec`, from the rate of fees seen in the trailing
   * ACCRUAL_WINDOW_SEC. feeReserve uses it for callback-metered apps (tokens, pages), whose future usage is not known
   * analytically the way heartbeat app-hours are, so that a payer cannot spend its whole share and starve settlement
   * on the period tail. The rate is taken over the actual span the samples cover and projected over the horizon
   * (rounded up, so a steady rate is never under-reserved). A single isolated event is not a rate: at least two
   * sampling buckets must hold usage, or the estimate is 0, so one burst does not reserve a whole window of fees.
   */
  projectedFee(app: string, horizonSec: number, now: number): bigint {
    if (horizonSec <= 0) return 0n;
    const buckets = this.accrual.get(app);
    if (!buckets) return 0n;
    const oldest = now - ACCRUAL_WINDOW_SEC;
    let sum = 0n;
    let min = Number.POSITIVE_INFINITY;
    let max = Number.NEGATIVE_INFINITY;
    let seen = 0;
    for (const [b, fee] of buckets) {
      if (b < oldest) continue;
      sum += fee;
      if (b < min) min = b;
      if (b > max) max = b;
      seen++;
    }
    // Need a sustained rate (two or more buckets over a real span), not one instantaneous burst.
    if (seen < 2 || sum <= 0n) return 0n;
    const span = max - min + ACCRUAL_BUCKET_SEC;
    if (span <= 0) return 0n;
    return (sum * BigInt(horizonSec) + BigInt(span) - 1n) / BigInt(span);
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
    // B1 (D-089): note the fee this event adds, so feeReserve can project future accrual for callback apps.
    this.noteAccrual(app, priceQuantity(quantity, rule, this.carryOf(app, unit)).fee, now);
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
      // No cut before the rebuild, so this is the event's first round and nothing of it was recorded: the
      // caller may send it again once the ledger rebuild is done (D-062).
      if (!this.rebuilt) throw new LedgerUnverifiedError("the usage ledger is being rebuilt; retry shortly");
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
    if (!this.rebuilt) throw new LedgerUnverifiedError("no report is cut before the ledger rebuild (D-062)");
    const open = this.state.open;
    if (this.isOpenEmpty(open)) return undefined;
    // Never a period that starts before one already signed (D-062).
    const periodStart = Math.max(this.state.periodStart, this.state.signedThrough ?? 0);
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
    this.state.signedThrough = Math.max(this.state.signedThrough ?? 0, periodEnd);
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

  /** Unpaid (report, app) pairs of reports that are not void, oldest first. */
  unpaid(): UnpaidEntry[] {
    const out: UnpaidEntry[] = [];
    for (const r of this.state.reports) {
      if (r.void) continue;
      for (const [app, p] of Object.entries(r.payments)) {
        if (p.status === "unpaid") out.push({ usageHash: r.usageHash, app, appId: p.appId, fee: BigInt(p.fee), createdAt: r.createdAt, submitted: r.submitted });
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
    return this.state.reports.filter((r) => !r.submitted && !r.void);
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
      if (r.void) continue;
      for (const p of Object.values(r.payments)) {
        metered += BigInt(p.fee);
        if (p.status === "unpaid") unpaid += BigInt(p.fee);
      }
    }
    return { metered, unpaid };
  }

  /** Drops old reports that are submitted and fully paid, or void. `signedThrough` keeps what they signed. */
  private prune(): void {
    this.state.signedThrough = this.knownSignedThrough();
    const settled = (r: StoredReport) => r.void === true || (r.submitted && Object.values(r.payments).every((p) => p.status === "paid"));
    const excess = this.state.reports.filter(settled).length - KEEP_SETTLED_REPORTS;
    if (excess <= 0) return;
    let dropped = 0;
    this.state.reports = this.state.reports.filter((r) => !(settled(r) && dropped++ < excess));
  }
}
