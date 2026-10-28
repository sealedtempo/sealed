import { CheerioCrawler, type CheerioCrawlerOptions, type Configuration } from '@crawlee/cheerio';
import type { RobotsTxtFile } from '@crawlee/utils';
import type { JobSpec } from '../job.js';
import type { RobotsPolicy } from '../robots.js';
import { handlePage, jobConfiguration, robotsPolicy, runWithAbort, sharedOptions } from './common.js';
import type { CrawlDeps, CrawlSink, CrawlSummary } from './types.js';

export class SealedCheerioCrawler extends CheerioCrawler {
  constructor(
    options: CheerioCrawlerOptions,
    config: Configuration,
    private readonly robots: RobotsPolicy,
  ) {
    super(options, config);
  }

  // Fetch robots.txt through sealed-egress with RFC 9309 failure handling (see robots.ts).
  protected override async getRobotsTxtFileForUrl(url: string): Promise<RobotsTxtFile | undefined> {
    if (!this.respectRobotsTxtFile) return undefined;
    return this.robots.forUrl(url);
  }
}

export function cheerioOptions(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink): CheerioCrawlerOptions {
  return {
    ...sharedOptions(spec, deps, sink),
    // HttpCrawler defaults to true; certificates are always verified.
    ignoreSslErrors: false,
    navigationTimeoutSecs: 30,
    preNavigationHooks: [
      (_ctx, gotOptions) => {
        // An honest bot: our own User-Agent, no generated browser headers.
        gotOptions.headers = { ...gotOptions.headers, 'user-agent': deps.userAgent };
        (gotOptions as { useHeaderGenerator?: boolean }).useHeaderGenerator = false;
      },
    ],
    requestHandler: async (ctx) => {
      await handlePage(ctx, ctx.response.statusCode ?? null, ctx.$, spec, sink);
    },
  };
}

export async function runCheerio(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink, signal: AbortSignal): Promise<CrawlSummary> {
  const robots = robotsPolicy(deps);
  const crawler = new SealedCheerioCrawler(cheerioOptions(spec, deps, sink), jobConfiguration(deps.memoryMbytes), robots);
  return runWithAbort(crawler, spec, robots, signal);
}
