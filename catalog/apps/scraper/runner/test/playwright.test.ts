import { existsSync } from 'node:fs';
import { log } from '@crawlee/core';
import { firefox } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { detectCrawlers } from '../src/crawl/index.js';
import { jobConfiguration } from '../src/crawl/common.js';
import { firefoxPrefs, playwrightOptions, runPlaywright } from '../src/crawl/playwright.js';
import { a6Job, expected, FIXTURE_HOST, memorySink, SITE, testDeps } from './helpers/fixture.js';
import { startStaticServer, type StaticServer } from './helpers/static-server.js';
import { startTestProxy, type TestProxy } from './helpers/test-proxy.js';

log.setLevel(log.LEVELS.OFF);

// Browser crawls need Playwright's Firefox build, which this build machine may not download.
// CI runs them with: pnpm exec playwright install firefox && pnpm test:playwright
const browserTests = process.env.SCRAPER_PLAYWRIGHT_TESTS === '1';

describe('Playwright crawler configuration (no browser needed)', () => {
  it('uses Firefox, honest headers, the egress proxy and keeps the sandbox on', () => {
    const opts = playwrightOptions(a6Job({ crawler: 'playwright', max_concurrency: 2 }), testDeps('http://172.30.0.2:3128'), memorySink().sink);
    expect(opts.launchContext?.launcher).toBe(firefox);
    expect(opts.launchContext?.useChrome).toBe(false);
    expect(opts.browserPoolOptions?.useFingerprints).toBe(false);
    expect(opts.proxyConfiguration).toBeDefined();
    expect(opts.respectRobotsTxtFile).toEqual({ userAgent: 'SealedScraper' });
    const launch = opts.launchContext?.launchOptions as { args?: string[]; acceptDownloads?: boolean; firefoxUserPrefs?: Record<string, unknown> };
    expect(launch.args ?? []).not.toContain('--no-sandbox');
    expect(launch.acceptDownloads).toBe(false);
    expect(launch.firefoxUserPrefs).toEqual(firefoxPrefs('SealedScraper/1.0 (+test)'));
    expect(jobConfiguration(1024).get('disableBrowserSandbox')).toBe(false);
  });

  it('routes loopback through the proxy and turns off background traffic', () => {
    const prefs = firefoxPrefs('UA');
    expect(prefs['general.useragent.override']).toBe('UA');
    expect(prefs['network.proxy.allow_hijacking_localhost']).toBe(true);
    expect(prefs['network.proxy.no_proxies_on']).toBe('');
    expect(prefs['media.peerconnection.enabled']).toBe(false);
    expect(prefs['network.trr.mode']).toBe(5);
    expect(Object.keys(prefs).some((k) => k.startsWith('security.sandbox'))).toBe(false);
  });

  it('offers playwright only when Firefox is installed', async () => {
    const crawlers = await detectCrawlers();
    expect(crawlers[0]).toBe('cheerio');
    expect(crawlers.includes('playwright')).toBe(existsSync(firefox.executablePath()));
    expect(await detectCrawlers(['cheerio'])).toEqual(['cheerio']);
  });
});

describe.runIf(browserTests)('Playwright Firefox crawl of the fixture site (CI only)', () => {
  let site: StaticServer;
  let proxy: TestProxy;

  beforeAll(async () => {
    site = await startStaticServer(SITE);
    proxy = await startTestProxy({ [`${FIXTURE_HOST}:80`]: site.port });
  });

  afterAll(async () => {
    await proxy.close();
    await site.close();
  });

  it('crawls the 10 pages through the proxy with the same extraction as Cheerio', async () => {
    const out = memorySink();
    await runPlaywright(a6Job({ crawler: 'playwright', max_concurrency: 2 }), testDeps(proxy.url), out.sink, new AbortController().signal);
    const byPath = Object.fromEntries(out.items.map((i) => [new URL(i.url).pathname, i.data]));
    for (const e of expected.items) {
      const { path, ...fields } = e;
      expect(byPath[path], path).toEqual(fields);
    }
    expect(out.items).toHaveLength(10);
    expect(out.skipped).toEqual([{ url: `http://${FIXTURE_HOST}/private/staff.html`, reason: 'robotsTxt' }]);
    const pages = proxy.log.filter((t) => t.target.endsWith('.html') || t.target.endsWith('/'));
    expect(pages.length).toBeGreaterThanOrEqual(10);
    for (const t of pages) expect(t.headers['user-agent']).toBe('SealedScraper/1.0 (+test)');
    expect(proxy.log.every((t) => t.target.startsWith(`http://${FIXTURE_HOST}/`))).toBe(true);
  }, 180_000);
});
