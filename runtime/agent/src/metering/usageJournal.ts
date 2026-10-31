// B2 (D-089): a small append-only write-ahead journal for accepted usage. recordUsage answers 202 only after the
// event is in the batched ledger save OR durably here, so a crash in the 2 s between ledger.record() and the next
// state save does not lose acknowledged usage. The batched full state save stays the steady-state path; this journal
// only covers the window between it and each accepted event.
//
// Durability contract (see StateStore.save and Agent.setupMetering):
// - append() writes and fsyncs one line before recordUsage returns 202; each entry carries a monotonic `seq`.
// - a full state save records, inside the snapshot, the journal `seq` it covers (`walThrough`), then drops journaled
//   entries up to it. Because a usage event is journaled BEFORE the ledger is mutated, any event the snapshot's
//   ledger reflects has `seq <= walThrough`, so it is never replayed twice (no double billing).
// - at boot, entries with `seq > walThrough` (and matching the current deployment) are replayed into the open period;
//   the normal holdForRebuild/adopt flow (D-062) then reconciles them against the platform's signed reports.
// Operations are serialized through one promise chain so a truncate can never drop an entry a concurrent append added.
import { open, readFile, rename, unlink } from "node:fs/promises";
import type { UsageUnitName } from "@sealed/core";

export interface JournalEntry {
  seq: number;
  /** The deployment the usage belongs to (D-058: one data disk may outlive a deployment id). */
  deploymentId: string;
  app: string;
  unit: UsageUnitName;
  /** Quantity as a decimal string (base units of the unit), matching the ledger. */
  quantity: string;
  at: number;
  /** The dedup key recordUsage used (`${app}:${id}`), so a client retry after a restart is still deduped. */
  id?: string;
}

export class UsageJournal {
  private seqNo = 0;
  /** Entries not yet known to be covered by a durable full state save, in seq order. */
  private pending: JournalEntry[] = [];
  private chain: Promise<void> = Promise.resolve();

  constructor(private readonly path: string) {}

  get seq(): number {
    return this.seqNo;
  }

  /** Loads the journal from disk for replay and positions the sequence past every entry already written. */
  static async load(path: string): Promise<{ journal: UsageJournal; entries: JournalEntry[] }> {
    const journal = new UsageJournal(path);
    const entries: JournalEntry[] = [];
    try {
      const text = await readFile(path, "utf8");
      for (const line of text.split("\n")) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as JournalEntry;
          // A partial last line from a crash mid-append was never acknowledged (no 202): skipping it loses nothing.
          if (typeof e.seq === "number" && typeof e.app === "string") entries.push(e);
        } catch {
          // ignore an unparseable (torn) line
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    journal.seqNo = entries.reduce((m, e) => Math.max(m, e.seq), 0);
    journal.pending = [...entries];
    return { journal, entries };
  }

  /** Appends one accepted event durably (fsync). Resolves once it is on disk, before recordUsage answers 202. */
  append(e: Omit<JournalEntry, "seq">): Promise<number> {
    const run = this.chain.then(async () => {
      const entry: JournalEntry = { ...e, seq: ++this.seqNo };
      const fh = await open(this.path, "a", 0o600);
      try {
        await fh.writeFile(`${JSON.stringify(entry)}\n`);
        await fh.sync();
      } finally {
        await fh.close();
      }
      this.pending.push(entry);
      return entry.seq;
    });
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** Drops entries a durable state save now covers (`seq <= through`) and compacts the file to the rest. */
  truncateThrough(through: number): Promise<void> {
    const run = this.chain.then(async () => {
      if (this.pending.length === 0 || this.pending[this.pending.length - 1]!.seq <= through) {
        // Everything is covered: remove the file so it does not grow unbounded.
        this.pending = [];
        await unlink(this.path).catch((err) => {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        });
        return;
      }
      this.pending = this.pending.filter((e) => e.seq > through);
      const tmp = `${this.path}.tmp`;
      const fh = await open(tmp, "w", 0o600);
      try {
        await fh.writeFile(this.pending.map((e) => `${JSON.stringify(e)}\n`).join(""));
        await fh.sync();
      } finally {
        await fh.close();
      }
      await rename(tmp, this.path);
    });
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
