import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../src/db/migrate.js';
import { MIGRATIONS } from '../src/db/migrations.js';
import { poolConfig } from '../src/db/pool.js';
import { PgRunStore } from '../src/db/store.js';
import { parseJobSpec, type JobSpec } from '../src/job.js';
import { createTestDatabase, hasPostgres, type TestDatabase } from './helpers/pg.js';

const spec = (extract: Record<string, string> = { name: 'h1' }): JobSpec => {
  const r = parseJobSpec({ start_urls: ['https://shop.example/'], extract });
  if (!r.ok) throw new Error('bad spec');
  return r.spec;
};

describe.runIf(hasPostgres)('PgRunStore on a throwaway PostgreSQL 17 cluster', () => {
  let db: TestDatabase;
  let store: PgRunStore;

  beforeAll(async () => {
    db = await createTestDatabase();
    store = new PgRunStore(db.pool);
  });

  afterAll(async () => {
    await db?.drop();
  });

  it('migrates once and is idempotent, also under concurrent starts', async () => {
    const results = await Promise.all([migrate(db.pool), migrate(db.pool)]);
    expect(results.flat()).toEqual(MIGRATIONS.map((m) => m.version));
    expect(await migrate(db.pool)).toEqual([]);
    const { rows } = await db.pool.query('SELECT version, name FROM schema_migrations ORDER BY version');
    expect(rows).toEqual(MIGRATIONS.map((m) => ({ version: m.version, name: m.name })));
  });

  it('creates, reads and lists runs', async () => {
    const a = await store.createRun(spec());
    const b = await store.createRun(spec({ title: 'h1', price: '.price' }));
    expect(a).toMatchObject({ status: 'queued', crawler: 'cheerio', pagesOk: 0, startedAt: null, error: null });
    expect((await store.getRun(b.id))?.spec.extract).toEqual({ title: 'h1', price: '.price' });
    expect(Object.keys((await store.getRun(b.id))!.spec.extract)).toEqual(['title', 'price']);
    expect(await store.getRun('not-a-uuid')).toBeNull();
    expect(await store.getRun('00000000-0000-4000-8000-000000000000')).toBeNull();
    const list = await store.listRuns({ limit: 10 });
    expect(list.map((r) => r.id).slice(0, 2)).toEqual([b.id, a.id]);
    expect(await store.listRuns({ limit: 1, offset: 1 })).toHaveLength(1);
  });

  it('moves runs through their states', async () => {
    const run = await store.createRun(spec());
    expect(await store.listRunIds('queued')).toContain(run.id);
    expect(await store.markRunning(run.id)).toBe(true);
    expect(await store.markRunning(run.id)).toBe(false);
    expect(await store.cancelQueued(run.id)).toBe(false);
    expect(await store.deleteRun(run.id)).toBe(false);
    await store.finishRun(run.id, 'succeeded');
    await store.finishRun(run.id, 'failed', 'late');
    const done = await store.getRun(run.id);
    expect(done).toMatchObject({ status: 'succeeded', error: null });
    expect(done?.startedAt).toBeInstanceOf(Date);
    expect(done?.finishedAt).toBeInstanceOf(Date);
  });

  it('cancels only queued runs and fails interrupted ones', async () => {
    const queued = await store.createRun(spec());
    const running = await store.createRun(spec());
    await store.markRunning(running.id);
    expect(await store.cancelQueued(queued.id)).toBe(true);
    expect(await store.failInterrupted('interrupted')).toBeGreaterThanOrEqual(1);
    expect(await store.getRun(running.id)).toMatchObject({ status: 'failed', error: 'interrupted' });
    expect((await store.getRun(queued.id))?.status).toBe('cancelled');
  });

  it('stores items with counters, keeps field order and strips NUL characters', async () => {
    const run = await store.createRun(spec({ b: 'h1', a: 'p' }));
    await store.addItem(run.id, { url: 'https://shop.example/1', statusCode: 200, data: { b: 'x\u0000y', a: null } });
    await store.addItem(run.id, { url: 'https://shop.example/2\u0000', statusCode: 200, data: { b: 'Café, "quoted"', a: 'ü' } });
    const items = await store.listItems(run.id, { limit: 10 });
    expect(items.map((i) => [i.url, i.data])).toEqual([
      ['https://shop.example/1', { b: 'xy', a: null }],
      ['https://shop.example/2', { b: 'Café, "quoted"', a: 'ü' }],
    ]);
    expect(typeof items[0]?.id).toBe('number');
    expect(await store.listItems(run.id, { after: items[0]!.id, limit: 10 })).toHaveLength(1);
    expect((await store.getRun(run.id))?.pagesOk).toBe(2);
  });

  it('counts failures and skips, logging events only when asked', async () => {
    const run = await store.createRun(spec());
    await store.addFailure(run.id, 'https://shop.example/x', 'HTTP 500', true);
    await store.addFailure(run.id, 'https://shop.example/y', 'HTTP 500', false);
    await store.addSkip(run.id, 'https://shop.example/private/', 'robotsTxt', true);
    expect(await store.getRun(run.id)).toMatchObject({ pagesFailed: 2, pagesSkipped: 1 });
    const events = await store.listEvents(run.id, { limit: 10 });
    expect(events.map((e) => [e.kind, e.url, e.detail])).toEqual([
      ['failed', 'https://shop.example/x', 'HTTP 500'],
      ['skipped', 'https://shop.example/private/', 'robotsTxt'],
    ]);
  });

  it('deletes finished runs with their items and events', async () => {
    const run = await store.createRun(spec());
    await store.addItem(run.id, { url: 'https://shop.example/1', statusCode: 200, data: { name: 'n' } });
    await store.addSkip(run.id, 'https://shop.example/p', 'robotsTxt', true);
    await store.finishRun(run.id, 'succeeded');
    expect(await store.deleteRun(run.id)).toBe(true);
    const { rows } = await db.pool.query('SELECT (SELECT count(*) FROM items WHERE run_id = $1) AS items, (SELECT count(*) FROM run_events WHERE run_id = $1) AS events', [run.id]);
    expect(rows[0]).toEqual({ items: '0', events: '0' });
  });

  it('pings', async () => {
    await expect(store.ping()).resolves.toBeUndefined();
  });
});

describe('poolConfig', () => {
  it('puts the secret password into the URL in memory only', () => {
    const cfg = poolConfig('postgres://scraper@scraper-db:5432/scraper', 'p@ss/word');
    expect(cfg.connectionString).toBe('postgres://scraper:p%40ss%2Fword@scraper-db:5432/scraper');
    expect(poolConfig('postgres://scraper@scraper-db:5432/scraper', undefined).connectionString).toBe('postgres://scraper@scraper-db:5432/scraper');
  });
});
