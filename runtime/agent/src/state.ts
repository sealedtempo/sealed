// Agent state that must survive restarts (unpaid reports, pricing remainders, payment status),
// kept on the encrypted data disk and written atomically.
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { emptyLedgerState, type LedgerState } from "./metering/ledger.js";

export interface PaymentStatus {
  /** First failed settlement of the current failure streak (unix seconds), null when healthy. */
  failingSince: number | null;
  paymentNeeded: boolean;
  lastAttemptAt?: number;
  lastPaidAt?: number;
  /** Content-free outcome code of the last settlement. */
  lastOutcome?: string;
}

export interface AgentState {
  version: 1;
  ledger: LedgerState;
  payments: PaymentStatus;
  /** Caddy config saved before switching to the payment-needed page. */
  caddyOriginal?: unknown;
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
      const parsed = JSON.parse(await readFile(path, "utf8")) as AgentState;
      if (parsed.version !== 1) throw new Error(`unsupported state version ${String(parsed.version)}`);
      return new StateStore(path, parsed);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      return new StateStore(path, emptyState(now));
    }
  }

  /** Serialized writes; each one replaces the file atomically. */
  save(): Promise<void> {
    const snapshot = JSON.stringify(this.state);
    this.chain = this.chain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      const tmp = `${this.path}.tmp`;
      await writeFile(tmp, snapshot, { mode: 0o600 });
      await rename(tmp, this.path);
    });
    return this.chain;
  }
}
