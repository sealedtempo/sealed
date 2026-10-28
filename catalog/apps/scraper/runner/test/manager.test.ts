import { describe, expect, it } from 'vitest';
import type { CrawlFn } from '../src/crawl/types.js';
import { parseJobSpec, type JobSpec } from '../src/job.js';
import type { Meter } from '../src/meter.js';
import { INTERRUPTED, RunManager, SHUTDOWN } from '../src/runs/manager.js';
import { MemoryRunStore } from './helpers/memory-store.js';

const spec = (urls = ['https://shop.example/']): JobSpec => {
  const r = parseJobSpec({ start_urls: urls, extract: { name: 'h1' } });
  if (!r.ok) throw new Error('bad spec');
  return r.spec;
};

function countingMeter() {
  const m = { added: 0, flushes: 0 };
  const meter: Meter = {
    add: (n = 1) => void (m.added += n),
    flush: async () => void m.flushes++,
    start() {},
    async stop() {},
  };
  return { meter, m };
}

const summary = { requestsFinished: 0, requestsFailed: 0, robots: {} };

// A crawl that emits `pages` items, then waits until released or aborted.
function controllableCrawl(pages = 2) {
  const started: string[] = [];
  const releases: Array<() => void> = [];
  let concurrent = 0;
  let maxConcurrent = 0;
  const crawl: CrawlFn = async (s, sink, signal) => {
    started.push(s.start_urls[0]!);
    concurrent++;
    maxConcurrent = Math.max(maxConcurrent, concurrent);
    try {
      for (let i = 0; i < pages; i++) await sink.item({ url: `${s.start_urls[0]}${i}`, statusCode: 200, data: { name: `n${i}` } });
      await new Promise<void>((resolve) => {
        releases.push(resolve);
        signal.addEventListener('abort', () => resolve(), { once: true });
      });
      return summary;
    } finally {
      concurrent--;
    }
  };
  return { crawl, started, releaseAll: () => releases.splice(0).forEach((r) => r()), stats: () => ({ maxConcurrent }) };
}

const tick = () => new Promise((r) => setTimeout(r, 10));

describe('RunManager', () => {
  it('runs a job, stores its items, meters each page and flushes after the run', async () => {
    const store = new MemoryRunStore();
    const { meter, m } = countingMeter();
    const c = controllableCrawl(3);
    const manager = new RunManager({ store, crawl: c.crawl, meter, maxRuns: 2 });
    const run = await manager.submit(spec());
    await tick();
    expect((await store.getRun(run.id))?.status).toBe('running');
    c.releaseAll();
    await manager.idle();
    expect(await store.getRun(run.id)).toMatchObject({ status: 'succeeded', pagesOk: 3, error: null });
    expect(store.items).toHaveLength(3);
    expect(m.added).toBe(3);
    expect(m.flushes).toBe(1);
  });

  it('runs at most maxRuns crawls at once, in submission order', async () => {
    const store = new MemoryRunStore();
    const c = controllableCrawl(0);
    const manager = new RunManager({ store, crawl: c.crawl, meter: countingMeter().meter, maxRuns: 2 });
    const ids = [];
    for (const host of ['a', 'b', 'c']) ids.push((await manager.submit(spec([`https://${host}.example/`]))).id);
    await tick();
    expect(c.started).toEqual(['https://a.example/', 'https://b.example/']);
    expect((await store.getRun(ids[2]!))?.status).toBe('queued');
    c.releaseAll();
    await tick();
    expect(c.started).toHaveLength(3);
    c.releaseAll();
    await manager.idle();
    expect(c.stats().maxConcurrent).toBe(2);
  });

  it('cancels queued runs before they start and stops running ones', async () => {
    const store = new MemoryRunStore();
    const c = controllableCrawl(1);
    const manager = new RunManager({ store, crawl: c.crawl, meter: countingMeter().meter, maxRuns: 1 });
    const first = await manager.submit(spec(['https://a.example/']));
    const second = await manager.submit(spec(['https://b.example/']));
    await tick();
    expect(await manager.cancel(second.id)).toBe('cancelled');
    expect(await manager.cancel(first.id)).toBe('stopping');
    await manager.idle();
    expect((await store.getRun(first.id))?.status).toBe('cancelled');
    expect((await store.getRun(second.id))?.status).toBe('cancelled');
    expect(c.started).toEqual(['https://a.example/']);
    expect(await manager.cancel(first.id)).toBe('finished');
    expect(await manager.cancel('00000000-0000-4000-8000-000000000000')).toBe('not-found');
    expect(await manager.cancel('not-a-uuid')).toBe('not-found');
  });

  it('stops a run at max_duration_minutes, keeps its pages and says why', async () => {
    const store = new MemoryRunStore();
    const c = controllableCrawl(2);
    const manager = new RunManager({ store, crawl: c.crawl, meter: countingMeter().meter, maxRuns: 1, minuteMs: 20 });
    const limited = parseJobSpec({ start_urls: ['https://shop.example/'], max_duration_minutes: 1 });
    if (!limited.ok) throw new Error('bad spec');
    const run = await manager.submit(limited.spec);
    await manager.idle();
    expect(await store.getRun(run.id)).toMatchObject({ status: 'succeeded', error: null, pagesOk: 2 });
    expect((await store.listEvents(run.id, { limit: 10 })).map((e) => [e.kind, e.detail])).toEqual([
      ['limit', 'stopped after 1 min (max_duration_minutes)'],
    ]);
  });

  it('marks a run failed when the crawl throws', async () => {
    const store = new MemoryRunStore();
    const crawl: CrawlFn = async () => {
      throw new Error('browser crashed');
    };
    const manager = new RunManager({ store, crawl, meter: countingMeter().meter, maxRuns: 1 });
    const run = await manager.submit(spec());
    await manager.idle();
    expect(await store.getRun(run.id)).toMatchObject({ status: 'failed', error: 'browser crashed' });
  });

  it('recovers after a restart: interrupted runs fail, queued runs start', async () => {
    const store = new MemoryRunStore();
    const left = await store.createRun(spec(['https://a.example/']));
    await store.markRunning(left.id);
    const waiting = await store.createRun(spec(['https://b.example/']));
    const c = controllableCrawl(0);
    const manager = new RunManager({ store, crawl: c.crawl, meter: countingMeter().meter, maxRuns: 1 });
    await manager.start();
    await tick();
    expect(await store.getRun(left.id)).toMatchObject({ status: 'failed', error: INTERRUPTED });
    expect(c.started).toEqual(['https://b.example/']);
    c.releaseAll();
    await manager.idle();
    expect((await store.getRun(waiting.id))?.status).toBe('succeeded');
  });

  it('on shutdown stops active runs, records why, and accepts nothing new', async () => {
    const store = new MemoryRunStore();
    const c = controllableCrawl(1);
    const manager = new RunManager({ store, crawl: c.crawl, meter: countingMeter().meter, maxRuns: 1 });
    const active = await manager.submit(spec(['https://a.example/']));
    const queued = await manager.submit(spec(['https://b.example/']));
    await tick();
    await manager.shutdown();
    expect(await store.getRun(active.id)).toMatchObject({ status: 'failed', error: SHUTDOWN });
    expect((await store.getRun(queued.id))?.status).toBe('queued');
    await expect(manager.submit(spec())).rejects.toThrow(/shutting down/);
  });

  it('caps stored events per run but keeps counting', async () => {
    const store = new MemoryRunStore();
    const crawl: CrawlFn = async (_s, sink) => {
      for (let i = 0; i < 3; i++) await sink.failed(`https://a.example/${i}`, 'HTTP 500');
      await sink.skipped('https://a.example/private', 'robotsTxt');
      return summary;
    };
    const manager = new RunManager({ store, crawl, meter: countingMeter().meter, maxRuns: 1, maxEventsPerRun: 2 });
    const run = await manager.submit(spec());
    await manager.idle();
    expect(await store.getRun(run.id)).toMatchObject({ pagesFailed: 3, pagesSkipped: 1 });
    expect(await store.listEvents(run.id, { limit: 10 })).toHaveLength(2);
  });
});
