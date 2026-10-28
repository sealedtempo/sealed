// Agent state that must survive restarts (unpaid reports, pricing remainders, payment status),
// kept on the encrypted data disk and written atomically.
import { mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname } from "node:path";
import { emptyLedgerState, type LedgerState } from "./metering/ledger.js";
import type { BudgetState } from "./payments/budget.js";

export interface PaymentStatus {
  /** First failed settlement of the current failure streak (unix seconds), null when healthy. */
  failingSince: number | null;
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

export interface AgentState {
  version: 1;
  /** The deployment this state belongs to. D-058 keeps the disk across stack upgrades, which change the id. */
  deploymentId?: string;
  ledger: LedgerState;
  payments: PaymentStatus;
  /** The shared daily spend budget (D-048). */
  budget?: BudgetState;
  /** Apps whose bootstrap job reported done (only jobs without a done file on the data disk). */
  bootstrapDone?: string[];
}

export function emptyState(now: number): AgentState {
  return { version: 1, ledger: emptyLedgerState(now), payments: { failingSince: null, paymentNeeded: false } };
}

export class StateStore {
  private chain: Promise<void> = Promise.resolve();
  constructor(
    private readonly path: string,
    public state: AgentState,
  ) {}

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
    const snapshot = JSON.stringify(this.state);
    const run = this.chain.catch(() => undefined).then(() => this.write(snapshot));
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
