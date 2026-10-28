import { PlaywrightCrawler, type Configuration, type PlaywrightCrawlerOptions } from '@crawlee/playwright';
import type { RobotsTxtFile } from '@crawlee/utils';
import { firefox } from 'playwright';
import type { JobSpec } from '../job.js';
import type { RobotsPolicy } from '../robots.js';
import { handlePage, jobConfiguration, robotsPolicy, runWithAbort, sharedOptions } from './common.js';
import { EGRESS_HEADER, egressVerdictFromHeader } from '../egress.js';
import type { CrawlDeps, CrawlSink, CrawlSummary } from './types.js';

// Playwright's Firefox (MPL-2.0), never Chromium: since Playwright 1.57 its Linux Chromium is Google's
// Chrome for Testing, whose license terms are unclear (D-022).
//
// Preferences keep every browser connection on the sealed-egress proxy (loopback included, so the
// proxy can refuse it) and turn off background traffic. The content sandbox keeps Firefox's default
// level; nothing here lowers it, and env-guard.ts strips the MOZ_DISABLE_*_SANDBOX variables.
export function firefoxPrefs(userAgent: string): Record<string, string | number | boolean> {
  return {
    'general.useragent.override': userAgent,
    'network.proxy.allow_hijacking_localhost': true,
    'network.proxy.no_proxies_on': '',
    'network.trr.mode': 5,
    'network.dns.disablePrefetch': true,
    'network.prefetch-next': false,
    'network.predictor.enabled': false,
    'network.http.speculative-parallel-limit': 0,
    'network.captive-portal-service.enabled': false,
    'network.connectivity-service.enabled': false,
    'media.peerconnection.enabled': false,
    'geo.enabled': false,
    'browser.safebrowsing.malware.enabled': false,
    'browser.safebrowsing.phishing.enabled': false,
    'browser.safebrowsing.downloads.enabled': false,
    'extensions.update.enabled': false,
    'datareporting.healthreport.uploadEnabled': false,
    'toolkit.telemetry.enabled': false,
  };
}

export class SealedPlaywrightCrawler extends PlaywrightCrawler {
  constructor(
    options: PlaywrightCrawlerOptions,
    config: Configuration,
    private readonly robots: RobotsPolicy,
  ) {
    super(options, config);
  }

  // robots.txt is always fetched Node-side through sealed-egress, never by the browser.
  protected override async getRobotsTxtFileForUrl(url: string): Promise<RobotsTxtFile | undefined> {
    if (!this.respectRobotsTxtFile) return undefined;
    return this.robots.forUrl(url);
  }
}

export function playwrightOptions(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink): PlaywrightCrawlerOptions {
  return {
    ...sharedOptions(spec, deps, sink),
    headless: true,
    navigationTimeoutSecs: 60,
    browserPoolOptions: { useFingerprints: false, retireBrowserAfterPageCount: 50 },
    launchContext: {
      launcher: firefox,
      useChrome: false,
      launchOptions: {
        headless: true,
        acceptDownloads: false,
        firefoxUserPrefs: firefoxPrefs(deps.userAgent),
      },
    },
    preNavigationHooks: [
      async (_ctx, gotoOptions) => {
        if (gotoOptions) gotoOptions.waitUntil = 'domcontentloaded';
      },
    ],
    requestHandler: async (ctx) => {
      const $ = await ctx.parseWithCheerio();
      const response = {
        statusCode: ctx.response?.status() ?? null,
        egress: egressVerdictFromHeader(ctx.response?.headers()[EGRESS_HEADER]),
      };
      await handlePage(ctx, response, $, spec, sink);
    },
  };
}

export async function runPlaywright(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink, signal: AbortSignal): Promise<CrawlSummary> {
  const robots = robotsPolicy(deps, sink);
  const crawler = new SealedPlaywrightCrawler(playwrightOptions(spec, deps, sink), jobConfiguration(deps.memoryMbytes), robots);
  return runWithAbort(crawler, spec, robots, signal);
}
