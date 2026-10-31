// Agent state that must survive restarts (unpaid reports, pricing remainders, payment status),
// kept on the encrypted data disk and written atomically.
import { mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname } from "node:path";
import { emptyLedgerState, type LedgerState } from "./metering/ledger.js";
import type { BudgetState } from "./payments/budget.js";

export interface PaymentStatus {
  /** First failed settlement of the current failure streak (unix seconds), null when healthy. */
  failingSince: number | null;
  /**
   * D-073: since when settlement has been deferred because the platform api could not be reached (its stored
   * reports could not be read, or it did not accept a report). While set, the grace period does not run; when
   * settlement resumes, failingSince moves forward by the deferral.
   */
  deferredSince?: number;
  paymentNeeded: boolean;
  lastAttemptAt?: number;
  lastPaidAt?: number;
  /** Content-free outcome code of the last settlement. */
  lastOutcome?: string;
  /** Legs that cannot be paid at the current FeeSplitter per-payment cap (last settlement). */
  overCap?: number;
  /** `${usageHash}:${app}` of legs the last settlement found it cannot pay, and why (review L2). */
  unpayable?: Record<string, "over_payment_cap" | "leg_token_mismatch" | "not_in_deployment">;
}

/**
 * A deployment this data disk ran before a same-salt stack upgrade (D-058), kept until everything it metered is
 * reported and paid under its own deploymentId (payments-5).
 */
export interface PreviousDeployment {
  deploymentId: string;
  /** When a boot found the state on the disk belonged to it. */
  since: number;
  ledger: LedgerState;
  payments: PaymentStatus;
}

export interface AgentState {
  version: 1;
  /** The deployment this state belongs to. D-058 keeps the disk across stack upgrades, which change the id. */
  deploymentId?: string;
  ledger: LedgerState;
  payments: PaymentStatus;
  /** Earlier deployments on this disk that still have usage to report or legs to pay (payments-5). */
  previous?: PreviousDeployment[];
  /** The shared daily spend budget (D-048). */
  budget?: BudgetState;
  /** Apps whose bootstrap job reported done (only jobs without a done file on the data disk). */
  bootstrapDone?: string[];
  /** B2 (D-089): the usage write-ahead journal sequence this saved snapshot already reflects; entries past it are replayed at boot. */
  walThrough?: number;
}

export function emptyState(now: number): AgentState {
  return { version: 1, ledger: emptyLedgerState(now), payments: { failingSince: null, paymentNeeded: false } };
}

/** B2 (D-089): the usage write-ahead journal StateStore keeps consistent with each saved snapshot. */
export interface WalCoordinator {
  /** The journal sequence covering every event appended so far. */
  seq(): number;
  /** Drop journaled entries the just-saved snapshot now reflects (seq <= through). */
  truncateThrough(through: number): Promise<void>;
}

export class StateStore {
  private chain: Promise<void> = Promise.resolve();
  private journal?: WalCoordinator;
  constructor(
    private readonly path: string,
    public state: AgentState,
  ) {}

  /** B2 (D-089): attach the usage write-ahead journal so each save stamps and compacts it. */
  attachJournal(journal: WalCoordinator): void {
    this.journal = journal;
  }

  static async open(path: string, now: number): Promise<StateStore> {
    try {
      const parsed = JSON.parse(await readFile(path, "utf8")) as AgentState & { caddyOriginal?: unknown };
      if (parsed.version !== 1) throw new Error(`unsupported state version ${String(parsed.version)}`);
      delete parsed.caddyOriginal; // written by agents before the Caddyfile-based switch
      return new StateStore(path, parsed);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      return new StateStore(path, emptyState(now));
    }
  }

  /**
   * Serialized writes of a snapshot taken now; each replaces the file atomically (fsync, then
   * rename). A failed write rejects only its own caller: the next save starts fresh.
   */
  save(): Promise<void> {
    // Stamp the journal sequence this snapshot covers BEFORE serializing, so the snapshot and walThrough agree. A
    // usage event is journaled before the ledger is mutated, so every event this snapshot's ledger holds has
    // seq <= through and is never replayed again (B2, D-089). Entries past `through` stay in the journal for replay.
    const through = this.journal?.seq();
    if (through !== undefined) this.state.walThrough = through;
    const snapshot = JSON.stringify(this.state);
    const run = this.chain
      .catch(() => undefined)
      .then(() => this.write(snapshot))
      .then(() => {
        if (through !== undefined) return this.journal?.truncateThrough(through).catch(() => undefined);
      });
    this.chain = run;
    return run;
  }

  private async write(snapshot: string): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    const fh = await open(tmp, "w", 0o600);
    try {
      await fh.writeFile(snapshot);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmp, this.path);
  }
}
