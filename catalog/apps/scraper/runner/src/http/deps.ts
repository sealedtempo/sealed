import type { Context } from 'hono';
import type { RunStore, Run } from '../db/store.js';
import type { CrawlerKind, JobSpec } from '../job.js';
import type { Logger } from '../log.js';
import type { CancelResult } from '../runs/manager.js';
import type { ClientPolicy } from '../client-policy.js';

export interface RunControl {
  submit(spec: JobSpec): Promise<Run>;
  cancel(id: string): Promise<CancelResult>;
}

export interface AppDeps {
  store: RunStore;
  runs: RunControl;
  crawlers: CrawlerKind[];
  log?: Logger;
  // Allowed peers (default DEFAULT_ALLOWED_CLIENTS) and how to read a request's peer address
  // (default: the Node socket). See clients.ts.
  clients?: ClientPolicy;
  remoteAddress?: (c: Context) => string | undefined;
  // The route's public origin (SEALED_PUBLIC_URL_SCRAPER); see security.ts.
  publicOrigin?: string;
}

export function clampInt(raw: string | undefined, fallback: number, min: number, max: number): number {
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
