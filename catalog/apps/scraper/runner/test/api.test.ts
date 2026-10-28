import { beforeEach, describe, expect, it } from 'vitest';
import type { RunStatus } from '../src/db/store.js';
import { createApp } from '../src/http/app.js';
import type { RunControl } from '../src/http/deps.js';
import type { CrawlerKind, JobSpec } from '../src/job.js';
import type { CancelResult } from '../src/runs/manager.js';
import { MemoryRunStore } from './helpers/memory-store.js';

class FakeRuns implements RunControl {
  submitted: JobSpec[] = [];
  constructor(private readonly store: MemoryRunStore) {}
  async submit(spec: JobSpec) {
    this.submitted.push(spec);
    return this.store.createRun(spec);
  }
  async cancel(id: string): Promise<CancelResult> {
    const run = await this.store.getRun(id);
    if (!run) return 'not-found';
    if (run.status === 'running') return 'stopping';
    if (await this.store.cancelQueued(id)) return 'cancelled';
    return 'finished';
  }
}

const JOB = {
  start_urls: ['https://shop.example/'],
  max_pages: 10,
  extract: { name: 'h1', price: '.price', note: '.note' },
};

let store: MemoryRunStore;
let runs: FakeRuns;
let app: ReturnType<typeof createApp>;
// The request's peer address; Caddy's fixed apps-network address unless a test changes it.
let peer: string | undefined;

function setup(crawlers: CrawlerKind[] = ['cheerio', 'playwright']) {
  store = new MemoryRunStore();
  runs = new FakeRuns(store);
  peer = '172.30.0.4';
  app = createApp({ store, runs, crawlers, remoteAddress: () => peer });
}

const postJson = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  app.request(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

async function seedRun(status: RunStatus = 'succeeded', spec: Partial<JobSpec> = {}) {
  const run = await store.createRun({
    start_urls: ['https://shop.example/'],
    max_pages: 10,
    crawler: 'cheerio',
    same_domain: true,
    extract: { name: 'h1', price: '.price', note: '.note' },
    max_concurrency: 4,
    max_requests_per_minute: 60,
    respect_robots: true,
    ...spec,
  });
  store.runs.get(run.id)!.status = status;
  return run;
}

beforeEach(() => setup());

describe('POST /api/v1/jobs', () => {
  it('creates a queued run from a valid job', async () => {
    const res = await postJson('/api/v1/jobs', JOB);
    expect(res.status).toBe(201);
    const { run } = (await res.json()) as { run: { id: string; status: string; spec: JobSpec; links: Record<string, string> } };
    expect(res.headers.get('location')).toBe(`/api/v1/runs/${run.id}`);
    expect(run.status).toBe('queued');
    expect(run.spec).toMatchObject({ crawler: 'cheerio', same_domain: true, respect_robots: true, max_concurrency: 4 });
    expect(run.links.export_csv).toBe(`/api/v1/runs/${run.id}/export.csv`);
    expect(runs.submitted).toHaveLength(1);
  });

  it('requires JSON', async () => {
    const res = await app.request('/api/v1/jobs', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
    expect(res.status).toBe(415);
  });

  it('rejects malformed JSON', async () => {
    const res = await app.request('/api/v1/jobs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"start_urls":' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: { code: 'bad_json' } });
  });

  it('returns every field error at once', async () => {
    const res = await postJson('/api/v1/jobs', { start_urls: ['http://10.0.0.1/'], max_pages: -1, crawler: 'lynx', extra: 1 });
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: { code: string; fields: { field: string }[] } };
    expect(body.error.code).toBe('invalid_job');
    expect(body.error.fields.map((f) => f.field).sort()).toEqual(['crawler', 'extra', 'max_pages', 'start_urls[0]']);
    expect(runs.submitted).toHaveLength(0);
  });

  it('refuses playwright jobs when the image has no browser', async () => {
    setup(['cheerio']);
    const res = await postJson('/api/v1/jobs', { ...JOB, crawler: 'playwright' });
    expect(res.status).toBe(422);
    expect(await res.json()).toMatchObject({ error: { fields: [{ field: 'crawler', message: 'playwright is not available in this image' }] } });
  });

  it('limits the body size', async () => {
    const res = await postJson('/api/v1/jobs', { ...JOB, padding: 'x'.repeat(70 * 1024) });
    expect(res.status).toBe(413);
  });

  it('refuses cross-site browser requests', async () => {
    expect((await postJson('/api/v1/jobs', JOB, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await postJson('/api/v1/jobs', JOB, { 'sec-fetch-site': 'same-site' })).status).toBe(403);
    expect((await postJson('/api/v1/jobs', JOB, { origin: 'https://evil.example', host: 'scraper.1-2-3-4.sslip.io' })).status).toBe(403);
    expect((await postJson('/api/v1/jobs', JOB, { origin: 'null', host: 'scraper.1-2-3-4.sslip.io' })).status).toBe(403);
    expect(
      (await postJson('/api/v1/jobs', JOB, { origin: 'https://scraper.1-2-3-4.sslip.io', host: 'scraper.1-2-3-4.sslip.io', 'sec-fetch-site': 'same-origin' }))
        .status,
    ).toBe(201);
  });
});

describe('client allowlist', () => {
  it('refuses every other container on the apps network, for the API and the UI', async () => {
    peer = '172.30.0.16';
    const create = await postJson('/api/v1/jobs', JOB);
    expect(create.status).toBe(403);
    expect(await create.json()).toEqual({ error: { code: 'forbidden_client', message: 'this client may not use the scraper' } });
    expect(runs.submitted).toEqual([]);
    expect((await app.request('/api/v1/runs')).status).toBe(403);
    expect((await app.request('/')).status).toBe(403);
    expect((await app.request('/runs/new', { method: 'POST' })).status).toBe(403);
  });

  it('refuses requests whose peer address is unknown', async () => {
    peer = undefined;
    expect((await app.request('/api/v1/runs')).status).toBe(403);
  });

  it('keeps /healthz open and accepts Caddy on a dual-stack socket', async () => {
    peer = '172.30.0.3';
    expect((await app.request('/healthz')).status).toBe(200);
    peer = '::ffff:172.30.0.4';
    expect((await app.request('/api/v1/runs')).status).toBe(200);
  });

  it('reads the peer from the Node socket by default', async () => {
    const real = createApp({ store, runs, crawlers: ['cheerio'] });
    const env = (address: string) => ({ incoming: { socket: { remoteAddress: address } } });
    expect((await real.request('/api/v1/runs', {}, env('172.30.0.4'))).status).toBe(200);
    expect((await real.request('/api/v1/runs', {}, env('172.30.0.9'))).status).toBe(403);
    expect((await real.request('/api/v1/runs')).status).toBe(403);
  });
});

describe('runs, items and events', () => {
  it('lists runs newest first and reads one', async () => {
    const a = await seedRun();
    const b = await seedRun('running');
    const list = (await (await app.request('/api/v1/runs?limit=1')).json()) as { runs: { id: string }[] };
    expect(list.runs.map((r) => r.id)).toEqual([b.id]);
    const one = (await (await app.request(`/api/v1/runs/${a.id}`)).json()) as { run: { id: string; pages: unknown } };
    expect(one.run).toMatchObject({ id: a.id, pages: { ok: 0, failed: 0, skipped: 0 } });
  });

  it('answers 404 for unknown and malformed ids', async () => {
    expect((await app.request('/api/v1/runs/00000000-0000-4000-8000-000000000000')).status).toBe(404);
    expect((await app.request('/api/v1/runs/not-a-uuid/items')).status).toBe(404);
    expect((await app.request('/api/v1/nope')).status).toBe(404);
    expect(await (await app.request('/api/v1/nope')).json()).toMatchObject({ error: { code: 'not_found' } });
  });

  it('pages through items with after and next', async () => {
    const run = await seedRun();
    for (let i = 0; i < 5; i++) await store.addItem(run.id, { url: `https://shop.example/${i}`, statusCode: 200, data: { name: `n${i}` } });
    const first = (await (await app.request(`/api/v1/runs/${run.id}/items?limit=2`)).json()) as { items: { id: number; url: string }[]; next: number };
    expect(first.items.map((i) => i.url)).toEqual(['https://shop.example/0', 'https://shop.example/1']);
    const rest = (await (await app.request(`/api/v1/runs/${run.id}/items?limit=10&after=${first.next}`)).json()) as {
      items: unknown[];
      next: number | null;
    };
    expect(rest.items).toHaveLength(3);
    expect(rest.next).toBeNull();
  });

  it('lists events', async () => {
    const run = await seedRun();
    await store.addSkip(run.id, 'https://shop.example/private/', 'robotsTxt', true);
    const body = (await (await app.request(`/api/v1/runs/${run.id}/events`)).json()) as { events: unknown[] };
    expect(body.events).toMatchObject([{ kind: 'skipped', url: 'https://shop.example/private/', detail: 'robotsTxt' }]);
  });

  it('reports capabilities and health', async () => {
    expect(await (await app.request('/api/v1/capabilities')).json()).toEqual({ crawlers: ['cheerio', 'playwright'] });
    expect((await app.request('/healthz')).status).toBe(200);
    store.failPing = true;
    expect((await app.request('/healthz')).status).toBe(503);
  });
});

describe('exports', () => {
  async function runWithItems() {
    const run = await seedRun();
    await store.addItem(run.id, { url: 'https://shop.example/a', statusCode: 200, data: { name: 'Brass hinge, 3 inch', price: '$4.50', note: null } });
    await store.addItem(run.id, { url: 'https://shop.example/b', statusCode: 200, data: { name: 'Wood screw "No. 8"', price: '=1+1', note: 'two\nlines' } });
    return run;
  }

  it('exports CSV with a header, RFC 4180 quoting and formula escaping', async () => {
    const run = await runWithItems();
    const res = await app.request(`/api/v1/runs/${run.id}/export.csv`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/csv');
    expect(res.headers.get('content-disposition')).toBe(`attachment; filename="scraper-run-${run.id}.csv"`);
    expect(await res.text()).toBe(
      'url,name,price,note\r\n' +
        'https://shop.example/a,"Brass hinge, 3 inch",$4.50,\r\n' +
        `https://shop.example/b,"Wood screw ""No. 8""",'=1+1,"two\nlines"\r\n`,
    );
  });

  it('can export raw values', async () => {
    const run = await runWithItems();
    const text = await (await app.request(`/api/v1/runs/${run.id}/export.csv?escape_formulas=false`)).text();
    expect(text.split('\r\n')[2]).toBe('https://shop.example/b,"Wood screw ""No. 8""",=1+1,"two\nlines"');
  });

  it('exports JSON as flat records in field order', async () => {
    const run = await runWithItems();
    const res = await app.request(`/api/v1/runs/${run.id}/export.json`);
    expect(res.headers.get('content-type')).toContain('application/json');
    const rows = (await res.json()) as Record<string, unknown>[];
    expect(rows).toEqual([
      { url: 'https://shop.example/a', name: 'Brass hinge, 3 inch', price: '$4.50', note: null },
      { url: 'https://shop.example/b', name: 'Wood screw "No. 8"', price: '=1+1', note: 'two\nlines' },
    ]);
    expect(Object.keys(rows[0]!)).toEqual(['url', 'name', 'price', 'note']);
  });

  it('exports an empty run', async () => {
    const run = await seedRun();
    expect(await (await app.request(`/api/v1/runs/${run.id}/export.json`)).json()).toEqual([]);
    expect(await (await app.request(`/api/v1/runs/${run.id}/export.csv`)).text()).toBe('url,name,price,note\r\n');
  });

  it('streams runs larger than one page of items', async () => {
    const run = await seedRun('succeeded', { extract: { n: 'p' } });
    for (let i = 0; i < 1203; i++) await store.addItem(run.id, { url: `https://shop.example/${i}`, statusCode: 200, data: { n: String(i) } });
    const rows = (await (await app.request(`/api/v1/runs/${run.id}/export.json`)).json()) as { n: string }[];
    expect(rows).toHaveLength(1203);
    expect(rows[1202]?.n).toBe('1202');
    const lines = (await (await app.request(`/api/v1/runs/${run.id}/export.csv`)).text()).trimEnd().split('\r\n');
    expect(lines).toHaveLength(1204);
  });
});

describe('cancel and delete', () => {
  it('cancels queued runs, stops running ones and refuses finished ones', async () => {
    const queued = await seedRun('queued');
    const running = await seedRun('running');
    const done = await seedRun('succeeded');
    expect(await (await app.request(`/api/v1/runs/${queued.id}/cancel`, { method: 'POST' })).json()).toMatchObject({
      result: 'cancelled',
      run: { status: 'cancelled' },
    });
    const stopping = await app.request(`/api/v1/runs/${running.id}/cancel`, { method: 'POST' });
    expect(stopping.status).toBe(202);
    expect(await stopping.json()).toMatchObject({ result: 'stopping' });
    expect((await app.request(`/api/v1/runs/${done.id}/cancel`, { method: 'POST' })).status).toBe(409);
    expect((await app.request('/api/v1/runs/00000000-0000-4000-8000-000000000000/cancel', { method: 'POST' })).status).toBe(404);
  });

  it('deletes only finished runs', async () => {
    const running = await seedRun('running');
    const done = await seedRun('failed');
    expect((await app.request(`/api/v1/runs/${running.id}`, { method: 'DELETE' })).status).toBe(409);
    expect((await app.request(`/api/v1/runs/${done.id}`, { method: 'DELETE' })).status).toBe(204);
    expect((await app.request(`/api/v1/runs/${done.id}`)).status).toBe(404);
  });
});

describe('UI', () => {
  it('serves the home page with a strict CSP', async () => {
    await seedRun();
    const res = await app.request('/');
    expect(res.status).toBe(200);
    const csp = res.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    const page = await res.text();
    expect(page).toContain('<form method="post" action="/jobs">');
    expect(page).toContain('https://shop.example/');
    expect(page).toContain('Outbound traffic only reaches destinations you approve.');
    expect(page).not.toMatch(/\u2014/);
    expect((await app.request('/assets/app.css')).headers.get('content-type')).toContain('text/css');
  });

  it('marks crawlers the image does not ship', async () => {
    setup(['cheerio']);
    expect(await (await app.request('/')).text()).toContain('<option value="playwright" disabled>playwright (not in this image)</option>');
  });

  it('creates a run from the form and redirects to it', async () => {
    const form = new URLSearchParams({
      start_urls: 'https://shop.example/',
      extract: 'name = h1\nprice = .price',
      max_pages: '5',
      crawler: 'cheerio',
      same_domain: 'on',
      respect_robots: 'on',
    });
    const res = await app.request('/jobs', { method: 'POST', body: form, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    expect(res.status).toBe(303);
    const id = runs.submitted.length === 1 ? (await store.listRuns({ limit: 1 }))[0]!.id : '';
    expect(res.headers.get('location')).toBe(`/runs/${id}`);
    expect(runs.submitted[0]).toMatchObject({ max_pages: 5, extract: { name: 'h1', price: '.price' }, same_domain: true });
  });

  it('re-renders the form with errors and keeps what was typed', async () => {
    const form = new URLSearchParams({ start_urls: 'http://localhost/', extract: 'oops', max_pages: '5' });
    const res = await app.request('/jobs', { method: 'POST', body: form, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    expect(res.status).toBe(422);
    const page = await res.text();
    expect(page).toContain('line 1 must look like name = selector');
    expect(page).toContain('must not target a local or internal name');
    expect(page).toContain('http://localhost/</textarea>');
    expect(runs.submitted).toHaveLength(0);
  });

  it('refuses cross-site form posts', async () => {
    const form = new URLSearchParams({ start_urls: 'https://shop.example/' });
    const res = await app.request('/jobs', {
      method: 'POST',
      body: form,
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'cross-site' },
    });
    expect(res.status).toBe(403);
  });

  it('renders scraped text as text, never as markup', async () => {
    const run = await seedRun();
    await store.addItem(run.id, { url: 'https://shop.example/x', statusCode: 200, data: { name: '<script>alert(1)</script>', price: '"><img src=x>', note: null } });
    const page = await (await app.request(`/runs/${run.id}`)).text();
    expect(page).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(page).not.toContain('<script>');
    expect(page).not.toContain('<img src=x>');
  });

  it('refreshes run pages only while the run is active', async () => {
    const running = await seedRun('running');
    const done = await seedRun('succeeded');
    expect(await (await app.request(`/runs/${running.id}`)).text()).toContain('http-equiv="refresh"');
    expect(await (await app.request(`/runs/${done.id}`)).text()).not.toContain('http-equiv="refresh"');
  });

  it('stops and deletes runs from the UI', async () => {
    const queued = await seedRun('queued');
    const stop = await app.request(`/runs/${queued.id}/cancel`, { method: 'POST' });
    expect(stop.status).toBe(303);
    expect((await store.getRun(queued.id))?.status).toBe('cancelled');
    const del = await app.request(`/runs/${queued.id}/delete`, { method: 'POST' });
    expect(del.headers.get('location')).toBe('/');
    expect(await store.getRun(queued.id)).toBeNull();
  });

  it('answers 404 pages for unknown runs', async () => {
    expect((await app.request('/runs/00000000-0000-4000-8000-000000000000')).status).toBe(404);
    expect((await app.request('/nope')).status).toBe(404);
  });
});
