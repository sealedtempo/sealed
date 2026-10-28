import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { FINISHED, type Run } from '../db/store.js';
import { parseJobSpec } from '../job.js';
import { clampInt, type AppDeps } from './deps.js';
import { csvExport, jsonExport, toStream } from './export.js';
import { eventJson, itemJson, runJson } from './serialize.js';

export const MAX_BODY_BYTES = 64 * 1024;

function apiError(c: Context, status: 400 | 403 | 404 | 409 | 413 | 415 | 422 | 503, code: string, message: string, extra = {}) {
  return c.json({ error: { code, message, ...extra } }, status);
}

function attachment(run: Run, ext: string): string {
  return `attachment; filename="scraper-run-${run.id}.${ext}"`;
}

// REST API, mounted at /api/v1.
//   POST   /jobs                  create a job; it runs once and returns its run (201)
//   GET    /runs                  list runs, newest first (?limit, ?offset)
//   GET    /runs/:id              run status and counters
//   GET    /runs/:id/items        items (?limit, ?after=<item id>)
//   GET    /runs/:id/events       failed and skipped URLs (?limit)
//   GET    /runs/:id/export.json  all items as a JSON array
//   GET    /runs/:id/export.csv   all items as CSV (?escape_formulas=false to keep raw values)
//   POST   /runs/:id/cancel       stop a queued or running run
//   DELETE /runs/:id              delete a finished run and its items
//   GET    /capabilities          crawlers available in this image
export function apiRoutes(deps: AppDeps): Hono {
  const api = new Hono();
  const { store, runs } = deps;

  const loadRun = async (c: Context): Promise<Run | Response> => {
    const run = await store.getRun(c.req.param('id') ?? '');
    return run ?? apiError(c, 404, 'not_found', 'run not found');
  };

  api.get('/capabilities', (c) => c.json({ crawlers: deps.crawlers }));

  api.post(
    '/jobs',
    bodyLimit({ maxSize: MAX_BODY_BYTES, onError: (c) => apiError(c, 413, 'too_large', `body must be at most ${MAX_BODY_BYTES} bytes`) }),
    async (c) => {
      const type = c.req.header('content-type') ?? '';
      if (!/^application\/json\b/i.test(type)) return apiError(c, 415, 'unsupported_media_type', 'send the job as application/json');
      let body: unknown;
      try {
        body = await c.req.json();
      } catch {
        return apiError(c, 400, 'bad_json', 'body is not valid JSON');
      }
      const parsed = parseJobSpec(body, deps.crawlers);
      if (!parsed.ok) return apiError(c, 422, 'invalid_job', 'the job is not valid', { fields: parsed.errors });
      const run = await runs.submit(parsed.spec);
      c.header('location', `/api/v1/runs/${run.id}`);
      return c.json({ run: runJson(run) }, 201);
    },
  );

  api.get('/runs', async (c) => {
    const limit = clampInt(c.req.query('limit'), 50, 1, 200);
    const offset = clampInt(c.req.query('offset'), 0, 0, 1_000_000);
    const list = await store.listRuns({ limit, offset });
    return c.json({ runs: list.map(runJson), limit, offset });
  });

  api.get('/runs/:id', async (c) => {
    const run = await loadRun(c);
    return run instanceof Response ? run : c.json({ run: runJson(run) });
  });

  api.get('/runs/:id/items', async (c) => {
    const run = await loadRun(c);
    if (run instanceof Response) return run;
    const limit = clampInt(c.req.query('limit'), 100, 1, 1000);
    const after = clampInt(c.req.query('after'), 0, 0, Number.MAX_SAFE_INTEGER);
    const items = await store.listItems(run.id, { after, limit });
    const last = items[items.length - 1];
    return c.json({ items: items.map(itemJson), next: items.length === limit && last ? last.id : null });
  });

  api.get('/runs/:id/events', async (c) => {
    const run = await loadRun(c);
    if (run instanceof Response) return run;
    const events = await store.listEvents(run.id, { limit: clampInt(c.req.query('limit'), 100, 1, 1000) });
    return c.json({ events: events.map(eventJson) });
  });

  api.get('/runs/:id/export.json', async (c) => {
    const run = await loadRun(c);
    if (run instanceof Response) return run;
    return c.body(toStream(jsonExport(store, run)), 200, {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': attachment(run, 'json'),
    });
  });

  api.get('/runs/:id/export.csv', async (c) => {
    const run = await loadRun(c);
    if (run instanceof Response) return run;
    const escapeFormulas = c.req.query('escape_formulas') !== 'false';
    return c.body(toStream(csvExport(store, run, { escapeFormulas })), 200, {
      'content-type': 'text/csv; charset=utf-8; header=present',
      'content-disposition': attachment(run, 'csv'),
    });
  });

  api.post('/runs/:id/cancel', async (c) => {
    const result = await runs.cancel(c.req.param('id'));
    if (result === 'not-found') return apiError(c, 404, 'not_found', 'run not found');
    if (result === 'finished') return apiError(c, 409, 'finished', 'the run already finished');
    const run = await store.getRun(c.req.param('id'));
    return c.json({ result, run: run ? runJson(run) : null }, 202);
  });

  api.delete('/runs/:id', async (c) => {
    const run = await loadRun(c);
    if (run instanceof Response) return run;
    if (!FINISHED.has(run.status)) return apiError(c, 409, 'active', 'cancel the run before deleting it');
    await store.deleteRun(run.id);
    return c.body(null, 204);
  });

  return api;
}
