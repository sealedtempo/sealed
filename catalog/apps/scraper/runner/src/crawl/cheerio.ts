import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { CheerioCrawler, type CheerioCrawlerOptions, type CheerioCrawlingContext, type Configuration } from '@crawlee/cheerio';
import type { Request } from '@crawlee/core';
import type { RobotsTxtFile } from '@crawlee/utils';
import type { JobSpec } from '../job.js';
import type { RobotsPolicy } from '../robots.js';
import { jobConfiguration, newRunState, pageHandler, robotsPolicy, runWithAbort, sharedOptions, startCrawlDelaySecs, throwOnFailedResponse, type PageResponse } from './common.js';
import { EGRESS_HEADER, egressVerdictFromHeader } from '../egress.js';
import { capResponse, DEFAULT_MAX_PAGE_BYTES } from './size-cap.js';
import type { CrawlDeps, CrawlSink, CrawlSummary } from './types.js';

function pageResponse(response: { statusCode?: number; headers: IncomingHttpHeaders }): PageResponse {
  return { statusCode: response.statusCode ?? null, egress: egressVerdictFromHeader(response.headers[EGRESS_HEADER]) };
}

export class SealedCheerioCrawler extends CheerioCrawler {
  constructor(
    options: CheerioCrawlerOptions,
    config: Configuration,
    private readonly robots: RobotsPolicy,
    private readonly maxPageBytes: number = DEFAULT_MAX_PAGE_BYTES,
  ) {
    super(options, config);
    // Before Crawlee's own content-type check, so an error status or an egress refusal is reported
    // as such and its body is never downloaded.
    this.postNavigationHooks.unshift(({ request, response }) => {
      if (response) throwOnFailedResponse(request, pageResponse(response));
    });
    // JSON bodies would be buffered whole only to be refused as "not HTML".
    this.supportedMimeTypes.delete('application/json');
  }

  // Every body Crawlee reads goes through here; see size-cap.ts.
  protected override async _parseResponse(request: Request, responseStream: IncomingMessage, crawlingContext: CheerioCrawlingContext) {
    return super._parseResponse(request, capResponse(request, responseStream, this.maxPageBytes), crawlingContext);
  }

  // Fetch robots.txt through sealed-egress with RFC 9309 failure handling (see robots.ts).
  protected override async getRobotsTxtFileForUrl(url: string): Promise<RobotsTxtFile | undefined> {
    if (!this.respectRobotsTxtFile) return undefined;
    return this.robots.forUrl(url);
  }
}

export function cheerioOptions(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink): CheerioCrawlerOptions {
  const state = newRunState();
  const handlePage = pageHandler(spec, sink, state);
  return {
    ...sharedOptions(spec, deps, sink, state),
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
      await handlePage(ctx, pageResponse(ctx.response), ctx.$);
    },
  };
}

export async function runCheerio(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink, signal: AbortSignal): Promise<CrawlSummary> {
  const robots = robotsPolicy(deps, sink);
  const crawlDelay = await startCrawlDelaySecs(spec, robots);
  const crawler = new SealedCheerioCrawler({ ...cheerioOptions(spec, deps, sink), sameDomainDelaySecs: crawlDelay }, jobConfiguration(deps.memoryMbytes), robots, deps.maxPageBytes);
  return runWithAbort(crawler, spec, robots, signal);
}
