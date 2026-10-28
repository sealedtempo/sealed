import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createProxyRobotsFetcher,
  DENY_ALL,
  interpretRobots,
  MAX_ROBOTS_BYTES,
  RobotsPolicy,
  RobotsRedirectLimitError,
  robotsUrlFor,
  type RobotsFetcher,
} from '../src/robots.js';
import { startTestProxy, type TestProxy } from './helpers/test-proxy.js';

const UA = 'SealedScraper';
const RULES = 'User-agent: *\nDisallow: /private/\n\nUser-agent: SealedScraper\nDisallow: /no-sealed/\n';

describe('interpretRobots (RFC 9309)', () => {
  it('parses 2xx bodies', () => {
    expect(interpretRobots({ status: 200, body: RULES })).toEqual({ outcome: 'parsed', body: RULES, reason: 'HTTP 200' });
  });

  it('caps parsed bodies at 500 KiB', () => {
    const big = 'a'.repeat(MAX_ROBOTS_BYTES + 10);
    expect(interpretRobots({ status: 200, body: big }).body).toHaveLength(MAX_ROBOTS_BYTES);
  });

  it.each([400, 401, 403, 404, 410, 451])('treats %i as unavailable: allow everything', (status) => {
    expect(interpretRobots({ status, body: 'User-agent: *\nDisallow: /' })).toEqual({ outcome: 'allow-all', body: '', reason: `unavailable: HTTP ${status}` });
  });

  it('treats a redirect loop beyond five hops as unavailable', () => {
    expect(interpretRobots(new RobotsRedirectLimitError('too many'))).toEqual({ outcome: 'allow-all', body: '', reason: 'unavailable: more than 5 redirects' });
  });

  it.each([429, 500, 502, 503, 504, 599, 100])('treats %i as unreachable: disallow everything', (status) => {
    expect(interpretRobots({ status, body: '' })).toEqual({ outcome: 'deny-all', body: DENY_ALL, reason: `unreachable: HTTP ${status}` });
  });

  it('treats network errors and timeouts as unreachable', () => {
    expect(interpretRobots(new Error('ECONNREFUSED'))).toMatchObject({ outcome: 'deny-all', reason: 'unreachable: ECONNREFUSED' });
  });

  it('treats sealed-egress refusals as unreachable, never as an origin 4xx', () => {
    // http targets: the proxy answers with 403 and its own marker.
    expect(interpretRobots({ status: 403, body: 'blocked', egress: 'blocked' })).toMatchObject({
      outcome: 'deny-all',
      reason: 'unreachable: refused by sealed-egress (blocked), add the host to egressAdditions.scraper',
    });
    expect(interpretRobots({ status: 429, body: '', egress: 'limited' }).outcome).toBe('deny-all');
    // https targets: the CONNECT fails.
    expect(interpretRobots(new Error('Proxy responded with 403 Forbidden: 0 bytes.'))).toMatchObject({
      outcome: 'deny-all',
      reason: 'unreachable: refused by sealed-egress, add the host to egressAdditions.scraper',
    });
  });
});

describe('RobotsPolicy', () => {
  const fake = (responses: Record<string, Awaited<ReturnType<RobotsFetcher>> | Error>) => {
    const calls: string[] = [];
    const fetcher: RobotsFetcher = async (url) => {
      calls.push(url);
      const r = responses[url];
      if (r === undefined || r instanceof Error) throw r ?? new Error('no route');
      return r;
    };
    return { fetcher, calls };
  };

  it('applies rules for our product token and the * group', async () => {
    const { fetcher } = fake({ 'https://shop.test/robots.txt': { status: 200, body: RULES } });
    const policy = new RobotsPolicy(fetcher);
    expect(await policy.isAllowed('https://shop.test/a.html', UA)).toBe(true);
    expect(await policy.isAllowed('https://shop.test/no-sealed/x', UA)).toBe(false);
    expect(await policy.isAllowed('https://shop.test/no-sealed/x', 'OtherBot')).toBe(true);
    expect(await policy.isAllowed('https://shop.test/private/x', 'OtherBot')).toBe(false);
    expect(policy.outcomes.get('https://shop.test/robots.txt')).toBe('parsed');
  });

  it('fetches once per origin', async () => {
    const { fetcher, calls } = fake({
      'https://shop.test/robots.txt': { status: 200, body: RULES },
      'http://shop.test/robots.txt': { status: 404, body: '' },
    });
    const policy = new RobotsPolicy(fetcher);
    await Promise.all([policy.forUrl('https://shop.test/a'), policy.forUrl('https://shop.test/b?x=1')]);
    await policy.forUrl('http://shop.test/c');
    expect(calls).toEqual(['https://shop.test/robots.txt', 'http://shop.test/robots.txt']);
  });

  it('denies everything when the fetch fails and allows everything on 404', async () => {
    const { fetcher } = fake({
      'https://down.test/robots.txt': { status: 503, body: 'try later' },
      'https://gone.test/robots.txt': { status: 404, body: 'Disallow: /' },
      'https://err.test/robots.txt': new Error('ETIMEDOUT'),
    });
    const policy = new RobotsPolicy(fetcher);
    expect(await policy.isAllowed('https://down.test/', UA)).toBe(false);
    expect(await policy.isAllowed('https://gone.test/anything', UA)).toBe(true);
    expect(await policy.isAllowed('https://err.test/', UA)).toBe(false);
  });

  it('reports each outcome once, with its reason', async () => {
    const { fetcher } = fake({
      'https://shop.test/robots.txt': { status: 200, body: RULES },
      'https://down.test/robots.txt': { status: 503, body: '' },
    });
    const seen: string[] = [];
    const policy = new RobotsPolicy(fetcher, undefined, (url, outcome, reason) => void seen.push(`${url} ${outcome} ${reason}`));
    await Promise.all([policy.forUrl('https://shop.test/a'), policy.forUrl('https://shop.test/b'), policy.forUrl('https://down.test/')]);
    expect(seen.sort()).toEqual(['https://down.test/robots.txt deny-all unreachable: HTTP 503', 'https://shop.test/robots.txt parsed HTTP 200']);
  });

  it('keeps its decision when reporting fails', async () => {
    const { fetcher } = fake({ 'https://shop.test/robots.txt': { status: 200, body: RULES } });
    const policy = new RobotsPolicy(fetcher, undefined, () => {
      throw new Error('db down');
    });
    expect(await policy.isAllowed('https://shop.test/no-sealed/x', UA)).toBe(false);
  });

  it('builds robots URLs from the origin', () => {
    expect(robotsUrlFor('https://shop.test:8443/a/b?c=1#d')).toBe('https://shop.test:8443/robots.txt');
  });
});

describe('createProxyRobotsFetcher', () => {
  let origin: Server;
  let proxy: TestProxy;
  const seen: { path: string; ua: string | undefined }[] = [];

  beforeAll(async () => {
    origin = createServer((req, res) => {
      seen.push({ path: req.url ?? '', ua: req.headers['user-agent'] });
      if (req.url === '/robots.txt' && req.headers.host === 'ok.test') return res.writeHead(200).end(RULES);
      if (req.headers.host === 'err.test') return res.writeHead(500).end('boom');
      if (req.headers.host === 'loop.test') return res.writeHead(302, { location: '/robots.txt' }).end();
      if (req.headers.host === 'big.test') return res.writeHead(200).end('#'.repeat(MAX_ROBOTS_BYTES * 2));
      res.writeHead(404).end();
    });
    await new Promise<void>((r) => origin.listen(0, '127.0.0.1', r));
    const port = (origin.address() as AddressInfo).port;
    proxy = await startTestProxy({ 'ok.test:80': port, 'err.test:80': port, 'loop.test:80': port, 'big.test:80': port, 'none.test:80': port });
  });

  afterAll(async () => {
    await proxy.close();
    await new Promise<void>((r) => origin.close(() => r()));
  });

  it('fetches through the proxy with our User-Agent and no generated headers', async () => {
    const fetch = createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'SealedScraper/1.0 (+test)' });
    expect(await fetch('http://ok.test/robots.txt')).toEqual({ status: 200, body: RULES, egress: null });
    const entry = proxy.log.find((e) => e.target === 'http://ok.test/robots.txt');
    expect(entry?.headers['user-agent']).toBe('SealedScraper/1.0 (+test)');
    expect(entry?.headers['sec-ch-ua']).toBeUndefined();
  });

  it('reports statuses instead of throwing, so the policy can apply RFC 9309', async () => {
    const fetch = createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'x' });
    expect((await fetch('http://err.test/robots.txt')).status).toBe(500);
    expect((await fetch('http://none.test/robots.txt')).status).toBe(404);
  });

  it('rejects a redirect loop with RobotsRedirectLimitError', async () => {
    const fetch = createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'x' });
    await expect(fetch('http://loop.test/robots.txt')).rejects.toBeInstanceOf(RobotsRedirectLimitError);
  });

  it('reads at most 500 KiB', async () => {
    const fetch = createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'x' });
    expect((await fetch('http://big.test/robots.txt')).body).toHaveLength(MAX_ROBOTS_BYTES);
  });

  it('marks an http destination the proxy refuses, so it is not mistaken for an origin 403', async () => {
    const fetch = createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'x' });
    expect(await fetch('http://blocked.test/robots.txt')).toMatchObject({ status: 403, egress: 'blocked' });
    const policy = new RobotsPolicy(fetch, proxy.url);
    expect(await policy.isAllowed('http://blocked.test/page', UA)).toBe(false);
    expect(policy.outcomes.get('http://blocked.test/robots.txt')).toBe('deny-all');
  });

  it('fails when the proxy refuses the destination (egress block) and when the proxy is down', async () => {
    const policy = new RobotsPolicy(createProxyRobotsFetcher({ proxyUrl: proxy.url, userAgent: 'x' }), proxy.url);
    expect(await policy.isAllowed('https://blocked.test/page', UA)).toBe(false);
    expect(policy.outcomes.get('https://blocked.test/robots.txt')).toBe('deny-all');
    const dead = createProxyRobotsFetcher({ proxyUrl: 'http://127.0.0.1:1', userAgent: 'x', timeoutMs: 2000 });
    await expect(dead('http://ok.test/robots.txt')).rejects.toThrow();
  });
});
