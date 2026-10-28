import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { UsageMeter, type UsageEvent } from '../src/meter.js';

function recordingFetch(statuses: number[] = []) {
  const bodies: UsageEvent[] = [];
  const urls: string[] = [];
  const impl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    urls.push(String(url));
    bodies.push(JSON.parse(String(init?.body)) as UsageEvent);
    const status = statuses.shift() ?? 202;
    return new Response(null, { status });
  });
  return { impl: impl as unknown as typeof fetch, bodies, urls, calls: impl };
}

const flushMicrotasks = () => new Promise((r) => setImmediate(r));
const strip = (b: UsageEvent) => ({ app: b.app, unit: b.unit, quantity: b.quantity });

afterEach(() => {
  vi.useRealTimers();
});

describe('UsageMeter', () => {
  it('batches pages into one event per flush', async () => {
    const f = recordingFetch();
    const meter = new UsageMeter({ agentUrl: 'http://sealed-agent:7070', flushMs: 1000, maxBatch: 100, fetch: f.impl });
    for (let i = 0; i < 7; i++) meter.add(1);
    expect(f.calls).not.toHaveBeenCalled();
    await meter.flush();
    expect(f.urls).toEqual(['http://sealed-agent:7070/v1/usage-events']);
    expect(f.bodies.map(strip)).toEqual([{ app: 'scraper', unit: 'pages', quantity: 7 }]);
    expect(f.bodies[0]?.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(meter.sentPages).toBe(7);
    expect(meter.pendingPages).toBe(0);
  });

  it('flushes on its interval', async () => {
    vi.useFakeTimers();
    const f = recordingFetch();
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 5000, maxBatch: 100, fetch: f.impl });
    meter.start();
    meter.add(3);
    await vi.advanceTimersByTimeAsync(4999);
    expect(f.calls).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(f.bodies.map(strip)).toEqual([{ app: 'scraper', unit: 'pages', quantity: 3 }]);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(f.calls).toHaveBeenCalledTimes(1);
    await meter.stop();
  });

  it('flushes early when a batch fills up', async () => {
    const f = recordingFetch();
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 60_000, maxBatch: 5, fetch: f.impl });
    for (let i = 0; i < 5; i++) meter.add(1);
    await flushMicrotasks();
    expect(f.bodies.map(strip)).toEqual([{ app: 'scraper', unit: 'pages', quantity: 5 }]);
  });

  it('keeps counting while a report is in flight', async () => {
    let release!: () => void;
    const bodies: UsageEvent[] = [];
    const slow = (async (_url: string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as UsageEvent);
      if (bodies.length === 1) await new Promise<void>((r) => (release = r));
      return new Response(null, { status: 202 });
    }) as unknown as typeof fetch;
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 1000, maxBatch: 1000, fetch: slow });
    meter.add(2);
    const first = meter.flush();
    meter.add(4);
    await flushMicrotasks();
    release();
    await first;
    await meter.flush();
    expect(bodies.map((b) => b.quantity)).toEqual([2, 4]);
    expect(new Set(bodies.map((b) => b.id)).size).toBe(2);
    expect(meter.sentPages).toBe(6);
  });

  it('retries a failed batch unchanged, with the same id and backoff', async () => {
    let now = 0;
    let n = 0;
    const f = recordingFetch([503, 500]);
    const meter = new UsageMeter({
      agentUrl: 'http://agent:7070',
      flushMs: 1000,
      maxBatch: 1000,
      fetch: f.impl,
      now: () => now,
      newId: () => `batch-${++n}`,
    });
    meter.add(10);
    await meter.flush(); // 503
    expect(meter.pendingPages).toBe(10);
    meter.add(1);
    expect(meter.pendingPages).toBe(11);
    await meter.flush(); // still backing off: no request
    expect(f.calls).toHaveBeenCalledTimes(1);
    now = 1000;
    await meter.flush(); // 500
    expect(f.calls).toHaveBeenCalledTimes(2);
    now = 2500; // backoff doubled to 2000 ms
    await meter.flush();
    expect(f.calls).toHaveBeenCalledTimes(2);
    now = 3000;
    await meter.flush(); // 202, then the page counted meanwhile goes in its own batch
    expect(f.bodies.map((b) => [b.id, b.quantity])).toEqual([
      ['batch-1', 10],
      ['batch-1', 10],
      ['batch-1', 10],
      ['batch-2', 1],
    ]);
    expect(meter.pendingPages).toBe(0);
    expect(meter.sentPages).toBe(11);
  });

  it('counts a batch once when the agent accepted it but the answer timed out', async () => {
    // A fake agent that dedupes on id, as sealed-agent does, and answers the first post too late.
    const accepted = new Map<string, number>();
    let calls = 0;
    const slowFirst = (async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as UsageEvent;
      if (!accepted.has(body.id)) accepted.set(body.id, body.quantity);
      if (++calls === 1) {
        await new Promise((r) => setTimeout(r, 50));
        init?.signal?.throwIfAborted();
      }
      return new Response(null, { status: 202 });
    }) as unknown as typeof fetch;
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 1, maxBatch: 1000, fetch: slowFirst, requestTimeoutMs: 10 });
    meter.add(7);
    await meter.flush(); // times out after the agent recorded it
    expect(meter.pendingPages).toBe(7);
    await new Promise((r) => setTimeout(r, 5));
    await meter.flush(); // the retry carries the same id
    expect(calls).toBe(2);
    expect([...accepted.values()].reduce((a, b) => a + b, 0)).toBe(7);
    expect(meter.sentPages).toBe(7);
  });

  it('treats network errors like failed reports', async () => {
    const failing = (async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 1000, maxBatch: 1000, fetch: failing });
    meter.add(3);
    await meter.flush();
    expect(meter.pendingPages).toBe(3);
  });

  it('ignores invalid quantities', async () => {
    const f = recordingFetch();
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 1000, maxBatch: 1000, fetch: f.impl });
    meter.add(0);
    meter.add(-2);
    meter.add(1.5);
    await meter.flush();
    expect(f.calls).not.toHaveBeenCalled();
  });

  it('flushes what is left on stop, ignoring backoff', async () => {
    let now = 0;
    const f = recordingFetch([500]);
    const meter = new UsageMeter({ agentUrl: 'http://agent:7070', flushMs: 1000, maxBatch: 1000, fetch: f.impl, now: () => now });
    meter.add(4);
    await meter.flush();
    await meter.stop();
    expect(f.bodies.map((b) => b.quantity)).toEqual([4, 4]);
    expect(f.bodies[0]?.id).toBe(f.bodies[1]?.id);
    expect(meter.pendingPages).toBe(0);
  });

  describe('against a local fake agent', () => {
    let server: Server | undefined;
    afterEach(async () => {
      await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    });

    it('posts JSON to /v1/usage-events', async () => {
      const received: { path: string; type: string | undefined; body: unknown }[] = [];
      server = createServer((req, res) => {
        let data = '';
        req.on('data', (c) => (data += c));
        req.on('end', () => {
          received.push({ path: req.url ?? '', type: req.headers['content-type'], body: JSON.parse(data) });
          res.writeHead(202).end();
        });
      });
      await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
      const meter = new UsageMeter({ agentUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, flushMs: 1000, maxBatch: 1000 });
      meter.add(2);
      await meter.stop();
      expect(received).toEqual([
        { path: '/v1/usage-events', type: 'application/json', body: { app: 'scraper', unit: 'pages', quantity: 2, id: expect.stringMatching(/^[0-9a-f-]{36}$/) } },
      ]);
    });
  });
});
