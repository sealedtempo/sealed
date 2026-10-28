import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { RunStore } from '../../src/db/store.js';
import { parseJobSpec, type JobSpec } from '../../src/job.js';

// The behaviour every RunStore must share, so the in-memory store used by the API and manager
// tests cannot hide a Postgres-only failure.

const spec = (): JobSpec => {
  const r = parseJobSpec({ start_urls: ['https://shop.example/'], extract: { name: 'h1' } });
  if (!r.ok) throw new Error('bad spec');
  return r.spec;
};

const MALFORMED = ['not-a-uuid', "1' OR '1'='1", '', '00000000-0000-4000-8000-00000000000Z'];
const item = { url: 'https://shop.example/1', statusCode: 200, data: { name: 'n' } };

export function describeRunStoreContract(name: string, enabled: boolean, open: () => Promise<{ store: RunStore; close(): Promise<void> }>) {
  describe.runIf(enabled)(`RunStore contract: ${name}`, () => {
    const withStore = (fn: (store: RunStore) => Promise<void>) => async () => {
      const { store, close } = await open();
      try {
        await fn(store);
      } finally {
        await close();
      }
    };

    it(
      'treats malformed and unknown ids as unknown runs',
      withStore(async (store) => {
        for (const id of [...MALFORMED, randomUUID()]) {
          expect(await store.getRun(id), id).toBeNull();
          expect(await store.markRunning(id), id).toBe(false);
          expect(await store.cancelQueued(id), id).toBe(false);
          expect(await store.deleteRun(id), id).toBe(false);
          await expect(store.finishRun(id, 'succeeded'), id).resolves.toBeUndefined();
          expect(await store.listItems(id, { limit: 10 }), id).toEqual([]);
          expect(await store.listEvents(id, { limit: 10 }), id).toEqual([]);
        }
      }),
    );

    it(
      'refuses to write items and events for malformed or unknown runs',
      withStore(async (store) => {
        for (const id of MALFORMED) {
          await expect(store.addItem(id, item), id).rejects.toThrow();
          await expect(store.addFailure(id, item.url, 'HTTP 500', false), id).rejects.toThrow();
          await expect(store.addSkip(id, item.url, 'robotsTxt', true), id).rejects.toThrow();
        }
        await expect(store.addItem(randomUUID(), item)).rejects.toThrow();
        await expect(store.addFailure(randomUUID(), item.url, 'HTTP 500', true)).rejects.toThrow();
      }),
    );

    it(
      'moves runs only along queued -> running -> finished',
      withStore(async (store) => {
        const run = await store.createRun(spec());
        expect(await store.deleteRun(run.id)).toBe(false);
        expect(await store.markRunning(run.id)).toBe(true);
        expect(await store.markRunning(run.id)).toBe(false);
        expect(await store.cancelQueued(run.id)).toBe(false);
        await store.finishRun(run.id, 'succeeded');
        await store.finishRun(run.id, 'failed', 'late');
        expect(await store.getRun(run.id)).toMatchObject({ status: 'succeeded', error: null });
        const queued = await store.createRun(spec());
        expect(await store.cancelQueued(queued.id)).toBe(true);
        expect(await store.deleteRun(queued.id)).toBe(true);
        expect(await store.getRun(queued.id)).toBeNull();
      }),
    );

    it(
      'counts items, failures and skips on the run',
      withStore(async (store) => {
        const run = await store.createRun(spec());
        await store.addItem(run.id, item);
        await store.addFailure(run.id, 'https://shop.example/x', 'HTTP 500', true);
        await store.addFailure(run.id, 'https://shop.example/y', 'HTTP 500', false);
        await store.addSkip(run.id, 'https://shop.example/p', 'robotsTxt', true);
        expect(await store.getRun(run.id)).toMatchObject({ pagesOk: 1, pagesFailed: 2, pagesSkipped: 1 });
        expect((await store.listEvents(run.id, { limit: 10 })).map((e) => e.kind)).toEqual(['failed', 'skipped']);
      }),
    );
  });
}
