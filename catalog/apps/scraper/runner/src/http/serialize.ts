import type { Item, Run, RunEvent } from '../db/store.js';

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export function runJson(run: Run) {
  const base = `/api/v1/runs/${run.id}`;
  return {
    id: run.id,
    status: run.status,
    crawler: run.crawler,
    created_at: iso(run.createdAt),
    started_at: iso(run.startedAt),
    finished_at: iso(run.finishedAt),
    pages: { ok: run.pagesOk, failed: run.pagesFailed, skipped: run.pagesSkipped },
    error: run.error,
    spec: run.spec,
    links: {
      self: base,
      items: `${base}/items`,
      events: `${base}/events`,
      export_json: `${base}/export.json`,
      export_csv: `${base}/export.csv`,
    },
  };
}

export function itemJson(item: Item) {
  return {
    id: item.id,
    url: item.url,
    status_code: item.statusCode,
    fetched_at: item.fetchedAt.toISOString(),
    data: item.data,
  };
}

export function eventJson(event: RunEvent) {
  return { id: event.id, kind: event.kind, url: event.url, detail: event.detail, at: event.at.toISOString() };
}
