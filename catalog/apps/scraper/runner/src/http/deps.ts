import type { RunStore, Run } from '../db/store.js';
import type { CrawlerKind, JobSpec } from '../job.js';
import type { Logger } from '../log.js';
import type { CancelResult } from '../runs/manager.js';

export interface RunControl {
  submit(spec: JobSpec): Promise<Run>;
  cancel(id: string): Promise<CancelResult>;
}

export interface AppDeps {
  store: RunStore;
  runs: RunControl;
  crawlers: CrawlerKind[];
  log?: Logger;
}

export function clampInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
