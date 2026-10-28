import { randomUUID } from 'node:crypto';
import type { CrawledItem } from '../../src/crawl/types.js';
import { FINISHED, isRunId, type EventKind, type Item, type NoteKind, type Run, type RunEvent, type RunStatus, type RunStore } from '../../src/db/store.js';
import type { JobSpec } from '../../src/job.js';

// In-memory RunStore with the same contract as PgRunStore (test/store.contract.test.ts checks both),
// for API and manager tests. Writes for malformed or unknown run ids fail the way Postgres does
// (uuid syntax error, foreign key violation).
export class MemoryRunStore implements RunStore {
  runs = new Map<string, Run>();
  items: Item[] = [];
  events = new Map<string, RunEvent[]>();
  failPing = false;
  private nextItem = 1;
  private nextEvent = 1;
  private clock = Date.parse('2026-10-28T12:00:00Z');

  async ping(): Promise<void> {
    if (this.failPing) throw new Error('db down');
  }

  async createRun(spec: JobSpec): Promise<Run> {
    const run: Run = {
      id: randomUUID(),
      status: 'queued',
      crawler: spec.crawler,
      spec,
      createdAt: new Date((this.clock += 1000)),
      startedAt: null,
      finishedAt: null,
      pagesOk: 0,
      pagesFailed: 0,
      pagesSkipped: 0,
      error: null,
    };
    this.runs.set(run.id, run);
    return { ...run };
  }

  async getRun(id: string): Promise<Run | null> {
    const run = this.runs.get(id);
    return run ? { ...run } : null;
  }

  async listRuns({ limit, offset = 0 }: { limit: number; offset?: number }): Promise<Run[]> {
    return [...this.runs.values()]
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(offset, offset + limit)
      .map((r) => ({ ...r }));
  }

  async listRunIds(status: RunStatus): Promise<string[]> {
    return [...this.runs.values()].filter((r) => r.status === status).map((r) => r.id);
  }

  async markRunning(id: string): Promise<boolean> {
    const run = this.runs.get(id);
    if (!run || run.status !== 'queued') return false;
    run.status = 'running';
    run.startedAt = new Date();
    return true;
  }

  async finishRun(id: string, status: RunStatus, error: string | null = null): Promise<void> {
    const run = this.runs.get(id);
    if (!run || FINISHED.has(run.status)) return;
    Object.assign(run, { status, error, finishedAt: new Date() });
  }

  async failInterrupted(message: string): Promise<number> {
    let n = 0;
    for (const run of this.runs.values()) {
      if (run.status === 'running') {
        Object.assign(run, { status: 'failed', error: message, finishedAt: new Date() });
        n++;
      }
    }
    return n;
  }

  async cancelQueued(id: string): Promise<boolean> {
    const run = this.runs.get(id);
    if (!run || run.status !== 'queued') return false;
    Object.assign(run, { status: 'cancelled', finishedAt: new Date() });
    return true;
  }

  async deleteRun(id: string): Promise<boolean> {
    const run = this.runs.get(id);
    if (!run || !FINISHED.has(run.status)) return false;
    this.runs.delete(id);
    this.items = this.items.filter((i) => i.runId !== id);
    this.events.delete(id);
    return true;
  }

  async addItem(runId: string, item: CrawledItem): Promise<void> {
    this.requireRun(runId);
    this.items.push({ id: this.nextItem++, runId, url: item.url, statusCode: item.statusCode, data: item.data, fetchedAt: new Date() });
    const run = this.runs.get(runId);
    if (run) run.pagesOk++;
  }

  async addFailure(runId: string, url: string, error: string, logEvent: boolean): Promise<void> {
    if (logEvent) this.requireRun(runId);
    else this.requireRunId(runId);
    const run = this.runs.get(runId);
    if (run) run.pagesFailed++;
    if (logEvent) this.pushEvent(runId, 'failed', url, error);
  }

  async addSkip(runId: string, url: string, reason: string, logEvent: boolean): Promise<void> {
    if (logEvent) this.requireRun(runId);
    else this.requireRunId(runId);
    const run = this.runs.get(runId);
    if (run) run.pagesSkipped++;
    if (logEvent) this.pushEvent(runId, 'skipped', url, reason);
  }

  async addNote(runId: string, kind: NoteKind, url: string, detail: string): Promise<void> {
    this.requireRun(runId);
    this.pushEvent(runId, kind, url, detail);
  }

  async listItems(runId: string, { after = 0, limit }: { after?: number; limit: number }): Promise<Item[]> {
    return this.items.filter((i) => i.runId === runId && i.id > after).slice(0, limit);
  }

  async listEvents(runId: string, { limit }: { limit: number }): Promise<RunEvent[]> {
    return (this.events.get(runId) ?? []).slice(0, limit);
  }

  private requireRunId(id: string): void {
    if (!isRunId(id)) throw new Error(`invalid input syntax for type uuid: "${id}"`);
  }

  private requireRun(id: string): void {
    this.requireRunId(id);
    if (!this.runs.has(id)) throw new Error('insert or update violates foreign key constraint');
  }

  private pushEvent(runId: string, kind: EventKind, url: string, detail: string) {
    const list = this.events.get(runId) ?? [];
    list.push({ id: this.nextEvent++, kind, url, detail, at: new Date() });
    this.events.set(runId, list);
  }
}
