import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { log } from '@crawlee/core';
import { serve, type ServerType } from '@hono/node-server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseAllowedClients } from '../src/client-policy.js';
import { createCrawl } from '../src/crawl/index.js';
import { migrate } from '../src/db/migrate.js';
import { PgRunStore } from '../src/db/store.js';
import { createApp } from '../src/http/app.js';
import { UsageMeter, type UsageEvent } from '../src/meter.js';
import { RunManager } from '../src/runs/manager.js';
import { parseCsv } from './helpers/csv-parse.js';
import { a6Job, expected, FIXTURE_HOST, SITE, testDeps } from './helpers/fixture.js';
import { createTestDatabase, hasPostgres, type TestDatabase } from './helpers/pg.js';
import { startStaticServer, type StaticServer } from './helpers/static-server.js';
import { startTestProxy, type TestProxy } from './helpers/test-proxy.js';

log.setLevel(log.LEVELS.OFF);

// The A6 acceptance flow on a laptop: the runner's HTTP server, its own Postgres, the fixture
// site behind a stand-in egress proxy, and a fake sealed-agent receiving usage events.
describe.runIf(hasPostgres)('end to end: job -> crawl -> Postgres -> CSV export -> metering', () => {
  let db: TestDatabase;
  let site: StaticServer;
  let proxy: TestProxy;
  let agent: Server;
  let http: ServerType;
  let base: string;
  let manager: RunManager;
  let meter: UsageMeter;
  const usage: UsageEvent[] = [];

  beforeAll(async () => {
    db = await createTestDatabase();
    await migrate(db.pool);
    site = await startStaticServer(SITE);
    proxy = await startTestProxy({ [`${FIXTURE_HOST}:80`]: site.port });
    agent = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        if (req.method === 'POST' && req.url === '/v1/usage-events') usage.push(JSON.parse(body) as UsageEvent);
        res.writeHead(202).end();
      });
    });
    await new Promise<void>((r) => agent.listen(0, '127.0.0.1', r));

    const store = new PgRunStore(db.pool);
    meter = new UsageMeter({ agentUrl: `http://127.0.0.1:${(agent.address() as AddressInfo).port}`, flushMs: 60_000, maxBatch: 4 });
    manager = new RunManager({ store, meter, maxRuns: 2, crawl: createCrawl(testDeps(proxy.url)) });
    await manager.start();
    const app = createApp({ store, runs: manager, crawlers: ['cheerio'] });
    http = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' });
    await new Promise<void>((r) => http.once('listening', () => r()));
    base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await manager?.shutdown();
    await meter?.stop();
    await new Promise<void>((r) => (http ? http.close(() => r()) : r()));
    await new Promise<void>((r) => (agent ? agent.close(() => r()) : r()));
    await proxy?.close();
    await site?.close();
    await db?.drop();
  });

  async function waitForRun(id: string): Promise<{ status: string; pages: { ok: number; failed: number; skipped: number } }> {
    for (let i = 0; i < 300; i++) {
      const { run } = (await (await fetch(`${base}/api/v1/runs/${id}`)).json()) as {
        run: { status: string; pages: { ok: number; failed: number; skipped: number } };
      };
      if (!['queued', 'running'].includes(run.status)) return run;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('run did not finish');
  }

  it('crawls the fixture site and exports the expected CSV', async () => {
    const job = a6Job();
    const created = await fetch(`${base}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(job),
    });
    expect(created.status).toBe(201);
    const { run } = (await created.json()) as { run: { id: string } };

    const done = await waitForRun(run.id);
    expect(done).toMatchObject({ status: 'succeeded', pages: { ok: 10, failed: 0, skipped: 1 } });

    const csv = await (await fetch(`${base}/api/v1/runs/${run.id}/export.csv`)).text();
    const [header, ...rows] = parseCsv(csv);
    expect(header).toEqual(['url', 'name', 'sku', 'price', 'category', 'description']);
    const byPath = new Map(rows.map((r) => [new URL(r[0]!).pathname, r.slice(1)]));
    expect(rows).toHaveLength(10);
    for (const e of expected.items) {
      expect(byPath.get(e.path), e.path).toEqual([e.name, e.sku, e.price, e.category, e.description]);
    }
    // The commas and quotes in the fixture really were quoted in the raw file.
    expect(csv).toContain('"Brass hinge, 3 inch"');
    expect(csv).toContain('"Wood screw ""No. 8"""');

    const json = (await (await fetch(`${base}/api/v1/runs/${run.id}/export.json`)).json()) as Record<string, string>[];
    expect(json).toHaveLength(10);

    const events = (await (await fetch(`${base}/api/v1/runs/${run.id}/events`)).json()) as { events: { kind: string; url: string }[] };
    expect(events.events).toEqual([
      expect.objectContaining({ kind: 'robots', url: `http://${FIXTURE_HOST}/robots.txt`, detail: 'parsed: HTTP 200' }),
      expect.objectContaining({ kind: 'skipped', url: `http://${FIXTURE_HOST}/private/staff.html` }),
    ]);

    // Metering: 10 successful pages reported in batches, never one event per page.
    expect(usage.every((u) => u.app === 'scraper' && u.unit === 'pages')).toBe(true);
    expect(usage.reduce((n, u) => n + u.quantity, 0)).toBe(10);
    expect(usage.length).toBeLessThan(10);
    expect(new Set(usage.map((u) => u.id)).size).toBe(usage.length);

    const page = await (await fetch(`${base}/runs/${run.id}`)).text();
    expect(page).toContain('Wood screw &quot;No. 8&quot;');
  });

  it('answers 404, not 500, for malformed run ids on every route', async () => {
    const post = (path: string) => fetch(`${base}${path}`, { method: 'POST', redirect: 'manual' });
    expect((await post('/api/v1/runs/not-a-uuid/cancel')).status).toBe(404);
    expect((await fetch(`${base}/api/v1/runs/not-a-uuid`, { method: 'DELETE' })).status).toBe(404);
    expect((await fetch(`${base}/api/v1/runs/not-a-uuid`)).status).toBe(404);
    expect((await fetch(`${base}/api/v1/runs/not-a-uuid/export.csv`)).status).toBe(404);
    expect((await post('/runs/not-a-uuid/cancel')).status).toBe(404);
    expect((await post('/runs/not-a-uuid/delete')).status).toBe(404);
    expect((await fetch(`${base}/runs/not-a-uuid`)).status).toBe(404);
  });

  it('refuses peers outside the client allowlist on a real socket, except /healthz', async () => {
    const guarded = createApp({ store: new PgRunStore(db.pool), runs: manager, crawlers: ['cheerio'], clients: parseAllowedClients('172.30.0.4') });
    const server = serve({ fetch: guarded.fetch, port: 0, hostname: '127.0.0.1' });
    await new Promise<void>((r) => server.once('listening', () => r()));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      expect((await fetch(`${url}/api/v1/runs`)).status).toBe(403);
      const post = await fetch(`${url}/api/v1/jobs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(a6Job()) });
      expect(post.status).toBe(403);
      expect((await fetch(`${url}/healthz`)).status).toBe(200);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('runs two jobs side by side with separate storage', async () => {
    const post = (job: unknown) =>
      fetch(`${base}/api/v1/jobs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(job) }).then(
        (r) => r.json() as Promise<{ run: { id: string } }>,
      );
    const [a, b] = await Promise.all([post(a6Job({ max_pages: 4 })), post(a6Job({ max_pages: 6 }))]);
    const [ra, rb] = await Promise.all([waitForRun(a.run.id), waitForRun(b.run.id)]);
    expect(ra.pages.ok).toBe(4);
    expect(rb.pages.ok).toBe(6);
  });
});
