import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { log } from '@crawlee/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cheerioOptions, runCheerio } from '../src/crawl/cheerio.js';
import { createCrawl } from '../src/crawl/index.js';
import { a6Job, expected, FIXTURE_HOST, memorySink, SITE, testDeps } from './helpers/fixture.js';
import { startStaticServer, type StaticServer } from './helpers/static-server.js';
import { startTestProxy, type TestProxy } from './helpers/test-proxy.js';

log.setLevel(log.LEVELS.OFF);

const never = new AbortController().signal;
const pathOf = (url: string) => new URL(url).pathname;

describe('Cheerio crawl of the fixture site through the egress proxy', () => {
  let site: StaticServer;
  let robots500: StaticServer;
  let codes: StaticServer;
  let proxy: TestProxy;
  const status = (code: number) => (_req: IncomingMessage, res: ServerResponse) =>
    res.writeHead(code, { 'content-type': 'text/html' }).end(`<h1 class="product-name">${code}</h1>`);

  beforeAll(async () => {
    site = await startStaticServer(SITE);
    robots500 = await startStaticServer(SITE, { '/robots.txt': (_req, res) => res.writeHead(503).end('maintenance') });
    codes = await startStaticServer(SITE, {
      '/401': status(401),
      '/403': status(403),
      '/404': status(404),
      '/429': status(429),
      '/500': status(500),
    });
    proxy = await startTestProxy(
      {
        [`${FIXTURE_HOST}:80`]: site.port,
        'down.test:80': robots500.port,
        'other.test:80': site.port,
        'codes.test:80': codes.port,
        'busy.test:80': site.port,
      },
      { limitOnce: ['busy.test:80'] },
    );
  });

  afterAll(async () => {
    await proxy.close();
    await Promise.all([site.close(), robots500.close(), codes.close()]);
  });

  it('fetches 401, 403, 404 and 429 once, and retries only 5xx', async () => {
    const out = memorySink();
    const paths = ['/401', '/403', '/404', '/429', '/500'];
    await runCheerio(a6Job({ start_urls: paths.map((p) => `http://codes.test${p}`), respect_robots: false }), testDeps(proxy.url), out.sink, never);
    const hits = (path: string) => codes.hits.filter((h) => h === path).length;
    expect(Object.fromEntries(paths.map((p) => [p, hits(p)]))).toEqual({ '/401': 1, '/403': 1, '/404': 1, '/429': 1, '/500': 3 });
    expect(out.items).toEqual([]);
    const failed = Object.fromEntries(out.failed.map((f) => [pathOf(f.url), f.error]));
    expect(failed).toEqual({ '/401': 'HTTP 401', '/403': 'HTTP 403', '/404': 'HTTP 404', '/429': 'HTTP 429', '/500': 'HTTP 500' });
  });

  it('does not retry destinations sealed-egress refuses, for https and http targets', async () => {
    const before = proxy.log.length;
    const out = memorySink();
    await runCheerio(
      a6Job({ start_urls: ['https://nowhere.test/', 'http://nowhere.test/x'], respect_robots: false }),
      testDeps(proxy.url),
      out.sink,
      never,
    );
    const refused = proxy.log.slice(before).filter((t) => !t.allowed).map((t) => `${t.method} ${t.target}`);
    expect(refused.sort()).toEqual(['CONNECT nowhere.test:443', 'GET http://nowhere.test/x']);
    expect(Object.fromEntries(out.failed.map((f) => [f.url, f.error]))).toEqual({
      'https://nowhere.test/': 'blocked by sealed-egress: nowhere.test:443 is not in egressAdditions.scraper',
      'http://nowhere.test/x': 'blocked by sealed-egress: nowhere.test:80 is not in egressAdditions.scraper',
    });
  });

  it('retries a page sealed-egress rate limited', async () => {
    const out = memorySink();
    await runCheerio(a6Job({ start_urls: ['http://busy.test/p02.html'], respect_robots: false, max_pages: 1 }), testDeps(proxy.url), out.sink, never);
    expect(out.failed).toEqual([]);
    expect(out.items.map((i) => i.data.sku)).toEqual(['FX-1002']);
  });

  it('crawls exactly the 10 pages, extracts every field and honours robots.txt', async () => {
    const before = proxy.log.length;
    const out = memorySink();
    const summary = await runCheerio(a6Job(), testDeps(proxy.url), out.sink, never);

    const byPath = Object.fromEntries(out.items.map((i) => [pathOf(i.url), i]));
    expect(Object.keys(byPath).sort()).toEqual(expected.items.map((e) => e.path).sort());
    for (const e of expected.items) {
      const { path, ...fields } = e;
      expect(byPath[path]?.data, path).toEqual(fields);
      expect(byPath[path]?.statusCode).toBe(200);
    }
    expect(out.skipped).toEqual([{ url: `http://${FIXTURE_HOST}/private/staff.html`, reason: 'robotsTxt' }]);
    expect(out.failed).toEqual([]);
    expect(summary.robots).toEqual({ [`http://${FIXTURE_HOST}/robots.txt`]: 'parsed' });

    const traffic = proxy.log.slice(before);
    // Every request, robots.txt included, went through the proxy; nothing left the fixture host.
    expect(traffic.every((t) => t.allowed && t.target.startsWith(`http://${FIXTURE_HOST}/`))).toBe(true);
    expect(traffic.filter((t) => t.target.endsWith('/robots.txt'))).toHaveLength(1);
    expect(traffic.some((t) => t.target.includes('example.com'))).toBe(false);
    expect(traffic.some((t) => t.target.includes('/private/'))).toBe(false);
    // An honest bot: our User-Agent and no generated browser fingerprint headers.
    for (const t of traffic) {
      expect(t.headers['user-agent']).toBe('SealedScraper/1.0 (+test)');
      expect(t.headers['sec-ch-ua']).toBeUndefined();
    }
  });

  it('stops at max_pages', async () => {
    const out = memorySink();
    await runCheerio(a6Job({ max_pages: 3 }), testDeps(proxy.url), out.sink, never);
    expect(out.items).toHaveLength(3);
    // Links beyond the cap are not reported one by one; only robots.txt skips remain.
    expect(out.skipped).toEqual([{ url: `http://${FIXTURE_HOST}/private/staff.html`, reason: 'robotsTxt' }]);
  });

  it('leaves the host only when same_domain is false, and then the egress proxy decides', async () => {
    const out = memorySink();
    const summary = await runCheerio(a6Job({ same_domain: false }), testDeps(proxy.url), out.sink, never);
    expect(out.items).toHaveLength(10);
    // example.com is not allowlisted: its robots.txt is unreachable, so the page is disallowed.
    expect(proxy.log.some((t) => t.method === 'CONNECT' && t.target === 'example.com:443' && !t.allowed)).toBe(true);
    expect(summary.robots['https://example.com/robots.txt']).toBe('deny-all');
    expect(out.skipped).toContainEqual({ url: 'https://example.com/', reason: 'robotsTxt' });

    // Without robots.txt the page fetch itself reaches the proxy and is refused.
    const raw = memorySink();
    await runCheerio(a6Job({ same_domain: false, respect_robots: false }), testDeps(proxy.url), raw.sink, never);
    expect(raw.items).toHaveLength(10);
    expect(raw.failed.map((f) => f.url).sort()).toEqual(['http://fixture.test/private/staff.html', 'https://example.com/']);
  });

  it('does not fetch robots.txt when respect_robots is false', async () => {
    const before = proxy.log.length;
    const out = memorySink();
    await runCheerio(a6Job({ respect_robots: false }), testDeps(proxy.url), out.sink, never);
    const traffic = proxy.log.slice(before);
    expect(traffic.some((t) => t.target.endsWith('/robots.txt'))).toBe(false);
    expect(traffic.filter((t) => t.target.endsWith('/private/staff.html'))).toHaveLength(1);
    // The disallowed page does not exist: a 404 is a failure, not a metered page, and is not retried.
    expect(out.failed).toEqual([{ url: `http://${FIXTURE_HOST}/private/staff.html`, error: 'HTTP 404' }]);
    expect(out.items).toHaveLength(10);
  });

  it('crawls nothing when robots.txt answers 5xx (RFC 9309: unreachable means disallow)', async () => {
    const out = memorySink();
    const summary = await runCheerio(a6Job({}, 'down.test'), testDeps(proxy.url), out.sink, never);
    expect(out.items).toEqual([]);
    expect(out.skipped).toEqual([{ url: 'http://down.test/', reason: 'robotsTxt' }]);
    expect(summary.robots).toEqual({ 'http://down.test/robots.txt': 'deny-all' });
    expect(robots500.hits).toEqual(['/robots.txt']);
  });

  it('stops gracefully when the run is cancelled', async () => {
    const abort = new AbortController();
    const out = memorySink(() => abort.abort());
    await runCheerio(a6Job({ max_concurrency: 1 }, 'other.test'), testDeps(proxy.url), out.sink, abort.signal);
    expect(out.items.length).toBeGreaterThanOrEqual(1);
    expect(out.items.length).toBeLessThan(10);
  });

  it('runs through createCrawl for cheerio jobs', async () => {
    const out = memorySink();
    await createCrawl(testDeps(proxy.url))(a6Job({ max_pages: 2 }), out.sink, never);
    expect(out.items).toHaveLength(2);
  });

  it('builds options with TLS verification on, the egress proxy, and the robots product token', () => {
    const opts = cheerioOptions(a6Job(), testDeps(proxy.url), memorySink().sink);
    expect(opts.ignoreSslErrors).toBe(false);
    expect(opts.proxyConfiguration).toBeDefined();
    expect(opts.respectRobotsTxtFile).toEqual({ userAgent: 'SealedScraper' });
    expect(opts.retryOnBlocked).toBe(false);
    expect(opts.maxRequestsPerCrawl).toBe(20);
    expect(opts.maxConcurrency).toBe(2);
  });
});

describe('TLS verification', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scraper-tls-'));
  const made = spawnSync(
    'openssl',
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=tls.test',
      '-addext', 'subjectAltName=DNS:tls.test'],
    { encoding: 'utf8' },
  );
  const haveOpenssl = made.status === 0;
  let server: HttpsServer;
  let proxy: TestProxy;

  beforeAll(async () => {
    if (!haveOpenssl) return;
    server = createHttpsServer(
      { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) },
      (req, res) => {
        if (req.url === '/robots.txt') return res.writeHead(404).end();
        res.writeHead(200, { 'content-type': 'text/html' }).end('<h1 class="product-name">secret</h1>');
      },
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    proxy = await startTestProxy({ 'tls.test:443': (server.address() as AddressInfo).port });
  });

  afterAll(async () => {
    if (!haveOpenssl) return;
    await proxy.close();
    await new Promise<void>((r) => server.close(() => r()));
  });

  it.runIf(haveOpenssl)('refuses a self-signed certificate (ignoreSslErrors is false)', async () => {
    const out = memorySink();
    await runCheerio(a6Job({ start_urls: ['https://tls.test/'], respect_robots: false }), testDeps(proxy.url), out.sink, never);
    expect(out.items).toEqual([]);
    expect(out.failed).toHaveLength(1);
    expect(out.failed[0]?.error).toMatch(/self[- ]signed|certificate/i);
    expect(proxy.log.some((t) => t.method === 'CONNECT' && t.target === 'tls.test:443')).toBe(true);
  });
});
