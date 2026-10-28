import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import type { CrawledItem } from '../crawl/types.js';
import type { ItemData } from '../extract.js';
import type { CrawlerKind, JobSpec } from '../job.js';
import { storableText, truncate } from '../text.js';

export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
export const FINISHED: ReadonlySet<RunStatus> = new Set(['succeeded', 'failed', 'cancelled']);

export interface Run {
  id: string;
  status: RunStatus;
  crawler: CrawlerKind;
  spec: JobSpec;
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
  pagesOk: number;
  pagesFailed: number;
  pagesSkipped: number;
  error: string | null;
}

export interface Item {
  id: number;
  runId: string;
  url: string;
  statusCode: number | null;
  data: ItemData;
  fetchedAt: Date;
}

// failed and skipped: one URL each, counted on the run. robots: what a robots.txt fetch decided.
// limit: why the run stopped early.
export type EventKind = 'failed' | 'skipped' | 'robots' | 'limit';
export type NoteKind = Exclude<EventKind, 'failed' | 'skipped'>;

export interface RunEvent {
  id: number;
  kind: EventKind;
  url: string;
  detail: string;
  at: Date;
}

// A malformed run id is an unknown run: reads give null or [] and state changes give false.
// Writing items or events for a malformed or unknown run id fails.
export interface RunStore {
  ping(): Promise<void>;
  createRun(spec: JobSpec): Promise<Run>;
  getRun(id: string): Promise<Run | null>;
  listRuns(options: { limit: number; offset?: number }): Promise<Run[]>;
  listRunIds(status: RunStatus): Promise<string[]>;
  // queued -> running; false when the run is no longer queued.
  markRunning(id: string): Promise<boolean>;
  finishRun(id: string, status: RunStatus, error?: string | null): Promise<void>;
  // running -> failed for runs a previous process left behind.
  failInterrupted(message: string): Promise<number>;
  // queued -> cancelled; false when the run already started.
  cancelQueued(id: string): Promise<boolean>;
  // Only finished runs can be deleted.
  deleteRun(id: string): Promise<boolean>;
  addItem(runId: string, item: CrawledItem): Promise<void>;
  addFailure(runId: string, url: string, error: string, logEvent: boolean): Promise<void>;
  addSkip(runId: string, url: string, reason: string, logEvent: boolean): Promise<void>;
  // An event that is not counted on the run.
  addNote(runId: string, kind: NoteKind, url: string, detail: string): Promise<void>;
  listItems(runId: string, options: { after?: number; limit: number }): Promise<Item[]>;
  listEvents(runId: string, options: { limit: number }): Promise<RunEvent[]>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function isRunId(id: string): boolean {
  return UUID.test(id);
}

const MAX_DETAIL = 1000;
const MAX_URL = 4096;

function clean(text: string, max: number): string {
  return truncate(storableText(text), max);
}

function cleanData(data: ItemData): ItemData {
  const out: ItemData = {};
  for (const [k, v] of Object.entries(data)) out[k] = v === null ? null : storableText(v);
  return out;
}

interface RunRow {
  id: string;
  status: RunStatus;
  crawler: CrawlerKind;
  spec: JobSpec;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  pages_ok: number;
  pages_failed: number;
  pages_skipped: number;
  error: string | null;
}

function toRun(r: RunRow): Run {
  return {
    id: r.id,
    status: r.status,
    crawler: r.crawler,
    spec: r.spec,
    createdAt: r.created_at,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    pagesOk: r.pages_ok,
    pagesFailed: r.pages_failed,
    pagesSkipped: r.pages_skipped,
    error: r.error,
  };
}

const RUN_COLUMNS =
  'id, status, crawler, spec, created_at, started_at, finished_at, pages_ok, pages_failed, pages_skipped, error';

export class PgRunStore implements RunStore {
  constructor(private readonly pool: pg.Pool) {}

  async ping(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  async createRun(spec: JobSpec): Promise<Run> {
    const { rows } = await this.pool.query<RunRow>(
      `INSERT INTO runs (id, status, crawler, spec) VALUES ($1, 'queued', $2, $3::json) RETURNING ${RUN_COLUMNS}`,
      [randomUUID(), spec.crawler, JSON.stringify(spec)],
    );
    return toRun(rows[0]!);
  }

  async getRun(id: string): Promise<Run | null> {
    if (!isRunId(id)) return null;
    const { rows } = await this.pool.query<RunRow>(`SELECT ${RUN_COLUMNS} FROM runs WHERE id = $1`, [id]);
    return rows[0] ? toRun(rows[0]) : null;
  }

  async listRuns({ limit, offset = 0 }: { limit: number; offset?: number }): Promise<Run[]> {
    const { rows } = await this.pool.query<RunRow>(
      `SELECT ${RUN_COLUMNS} FROM runs ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    return rows.map(toRun);
  }

  async listRunIds(status: RunStatus): Promise<string[]> {
    const { rows } = await this.pool.query<{ id: string }>(
      'SELECT id FROM runs WHERE status = $1 ORDER BY created_at, id',
      [status],
    );
    return rows.map((r) => r.id);
  }

  async markRunning(id: string): Promise<boolean> {
    if (!isRunId(id)) return false;
    const res = await this.pool.query(
      "UPDATE runs SET status = 'running', started_at = now() WHERE id = $1 AND status = 'queued'",
      [id],
    );
    return res.rowCount === 1;
  }

  async finishRun(id: string, status: RunStatus, error: string | null = null): Promise<void> {
    if (!isRunId(id)) return;
    await this.pool.query(
      "UPDATE runs SET status = $2, finished_at = now(), error = $3 WHERE id = $1 AND status IN ('queued', 'running')",
      [id, status, error ? clean(error, MAX_DETAIL) : null],
    );
  }

  async failInterrupted(message: string): Promise<number> {
    const res = await this.pool.query(
      "UPDATE runs SET status = 'failed', finished_at = now(), error = $1 WHERE status = 'running'",
      [message],
    );
    return res.rowCount ?? 0;
  }

  async cancelQueued(id: string): Promise<boolean> {
    if (!isRunId(id)) return false;
    const res = await this.pool.query(
      "UPDATE runs SET status = 'cancelled', finished_at = now() WHERE id = $1 AND status = 'queued'",
      [id],
    );
    return res.rowCount === 1;
  }

  async deleteRun(id: string): Promise<boolean> {
    if (!isRunId(id)) return false;
    const res = await this.pool.query(
      "DELETE FROM runs WHERE id = $1 AND status IN ('succeeded', 'failed', 'cancelled')",
      [id],
    );
    return res.rowCount === 1;
  }

  async addItem(runId: string, item: CrawledItem): Promise<void> {
    await this.pool.query(
      `WITH ins AS (
         INSERT INTO items (run_id, url, status_code, data) VALUES ($1, $2, $3, $4::jsonb) RETURNING 1
       )
       UPDATE runs SET pages_ok = pages_ok + (SELECT count(*) FROM ins) WHERE id = $1`,
      [runId, clean(item.url, MAX_URL), item.statusCode, JSON.stringify(cleanData(item.data))],
    );
  }

  async addFailure(runId: string, url: string, error: string, logEvent: boolean): Promise<void> {
    await this.addCounted(runId, 'failed', 'pages_failed', url, error, logEvent);
  }

  async addSkip(runId: string, url: string, reason: string, logEvent: boolean): Promise<void> {
    await this.addCounted(runId, 'skipped', 'pages_skipped', url, reason, logEvent);
  }

  async addNote(runId: string, kind: NoteKind, url: string, detail: string): Promise<void> {
    await this.pool.query('INSERT INTO run_events (run_id, kind, url, detail) VALUES ($1, $2, $3, $4)', [
      runId,
      kind,
      clean(url, MAX_URL),
      clean(detail, MAX_DETAIL),
    ]);
  }

  private async addCounted(
    runId: string,
    kind: 'failed' | 'skipped',
    column: 'pages_failed' | 'pages_skipped',
    url: string,
    detail: string,
    logEvent: boolean,
  ): Promise<void> {
    if (!logEvent) {
      await this.pool.query(`UPDATE runs SET ${column} = ${column} + 1 WHERE id = $1`, [runId]);
      return;
    }
    await this.pool.query(
      `WITH ins AS (
         INSERT INTO run_events (run_id, kind, url, detail) VALUES ($1, $2, $3, $4) RETURNING 1
       )
       UPDATE runs SET ${column} = ${column} + (SELECT count(*) FROM ins) WHERE id = $1`,
      [runId, kind, clean(url, MAX_URL), clean(detail, MAX_DETAIL)],
    );
  }

  async listItems(runId: string, { after = 0, limit }: { after?: number; limit: number }): Promise<Item[]> {
    if (!isRunId(runId)) return [];
    const { rows } = await this.pool.query<{
      id: string;
      run_id: string;
      url: string;
      status_code: number | null;
      data: ItemData;
      fetched_at: Date;
    }>(
      'SELECT id, run_id, url, status_code, data, fetched_at FROM items WHERE run_id = $1 AND id > $2 ORDER BY id LIMIT $3',
      [runId, after, limit],
    );
    return rows.map((r) => ({
      id: Number(r.id),
      runId: r.run_id,
      url: r.url,
      statusCode: r.status_code,
      data: r.data,
      fetchedAt: r.fetched_at,
    }));
  }

  async listEvents(runId: string, { limit }: { limit: number }): Promise<RunEvent[]> {
    if (!isRunId(runId)) return [];
    const { rows } = await this.pool.query<{ id: string; kind: EventKind; url: string; detail: string; at: Date }>(
      'SELECT id, kind, url, detail, at FROM run_events WHERE run_id = $1 ORDER BY id LIMIT $2',
      [runId, limit],
    );
    return rows.map((r) => ({ id: Number(r.id), kind: r.kind, url: r.url, detail: r.detail, at: r.at }));
  }
}
