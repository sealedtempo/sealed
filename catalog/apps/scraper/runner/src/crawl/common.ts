import { Configuration, ProxyConfiguration, type EnqueueLinksOptions, type RequestOptions } from '@crawlee/core';
import { MemoryStorage } from '@crawlee/memory-storage';
import { extractFields, type ParsedPage } from '../extract.js';
import type { JobSpec } from '../job.js';
import { errorMessage } from '../log.js';
import { createProxyRobotsFetcher, RobotsPolicy } from '../robots.js';
import { checkTargetUrl } from '../url-policy.js';
import type { CrawlDeps, CrawlSink, CrawlSummary } from './types.js';

// Every job gets its own Configuration and an explicit non-persistent MemoryStorage: its own request
// queue, session pool and statistics, nothing on disk, and immune to a stray CRAWLEE_PERSIST_STORAGE.
export function jobConfiguration(memoryMbytes: number): Configuration {
  return new Configuration({
    storageClient: new MemoryStorage({ persistStorage: false, writeMetadata: false }),
    persistStorage: false,
    purgeOnStart: true,
    headless: true,
    disableBrowserSandbox: false,
    memoryMbytes,
  });
}

export function egressProxy(proxyUrl: string | undefined): ProxyConfiguration | undefined {
  return proxyUrl ? new ProxyConfiguration({ proxyUrls: [proxyUrl] }) : undefined;
}

export function robotsPolicy(deps: CrawlDeps): RobotsPolicy {
  const fetcher = deps.robotsFetcher ?? createProxyRobotsFetcher({ proxyUrl: deps.proxyUrl, userAgent: deps.userAgent });
  return new RobotsPolicy(fetcher, deps.proxyUrl);
}

// Crawlee reports a skipped link once per page that links to it, and reports max_pages
// ("limit", "enqueueLimit") even for links that were already crawled. Report each skipped URL once,
// and leave max_pages out: the run's page cap is already part of its spec.
const LIMIT_REASONS = new Set(['limit', 'enqueueLimit']);
const MAX_TRACKED_SKIPS = 100_000;

export function skipReporter(sink: CrawlSink) {
  const seen = new Set<string>();
  return async ({ url, reason }: { url: string; reason: string }) => {
    if (LIMIT_REASONS.has(reason) || seen.has(url)) return;
    if (seen.size < MAX_TRACKED_SKIPS) seen.add(url);
    await sink.skipped(url, reason);
  };
}

// Options shared by the Cheerio and Playwright crawlers.
export function sharedOptions(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink) {
  return {
    proxyConfiguration: egressProxy(deps.proxyUrl),
    respectRobotsTxtFile: spec.respect_robots ? { userAgent: deps.robotsUserAgent } : false,
    maxRequestsPerCrawl: spec.max_pages,
    minConcurrency: 1,
    maxConcurrency: spec.max_concurrency,
    maxRequestsPerMinute: spec.max_requests_per_minute,
    maxRequestRetries: 2,
    // Rotating sessions to get past 401/403/429 or a refusing proxy is not what an honest bot does.
    maxSessionRotations: 1,
    requestHandlerTimeoutSecs: 60,
    retryOnBlocked: false,
    onSkippedRequest: skipReporter(sink),
    failedRequestHandler: async ({ request }: { request: { url: string } }, error: Error) => {
      await sink.failed(request.url, errorMessage(error));
    },
  };
}

export function enqueueOptions(spec: JobSpec): EnqueueLinksOptions {
  return {
    strategy: spec.same_domain ? 'same-hostname' : 'all',
    transformRequestFunction: (req: RequestOptions) => (checkTargetUrl(req.url) ? false : req),
  };
}

export class HttpStatusError extends Error {}

interface PageContext {
  request: { url: string; loadedUrl?: string; noRetry: boolean };
  enqueueLinks: (options: EnqueueLinksOptions) => Promise<unknown>;
}

// Successful pages only: a 4xx or 5xx final status is recorded as a failure, without retries for 4xx.
export async function handlePage(
  ctx: PageContext,
  statusCode: number | null,
  $: ParsedPage | undefined,
  spec: JobSpec,
  sink: CrawlSink,
): Promise<void> {
  if (statusCode !== null && statusCode >= 400) {
    ctx.request.noRetry = statusCode < 500;
    throw new HttpStatusError(`HTTP ${statusCode}`);
  }
  if (!$) {
    ctx.request.noRetry = true;
    throw new HttpStatusError('response is not HTML');
  }
  const url = ctx.request.loadedUrl ?? ctx.request.url;
  await ctx.enqueueLinks(enqueueOptions(spec));
  await sink.item({ url, statusCode, data: extractFields($, spec.extract, url) });
}

interface Stoppable {
  stop(reason?: string): void;
  run(requests: string[]): Promise<{ requestsFinished: number; requestsFailed: number }>;
}

export async function runWithAbort(
  crawler: Stoppable,
  spec: JobSpec,
  robots: RobotsPolicy,
  signal: AbortSignal,
): Promise<CrawlSummary> {
  if (signal.aborted) return { requestsFinished: 0, requestsFailed: 0, robots: {} };
  const onAbort = () => crawler.stop('run cancelled');
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    const stats = await crawler.run(spec.start_urls);
    return {
      requestsFinished: stats.requestsFinished,
      requestsFailed: stats.requestsFailed,
      robots: Object.fromEntries(robots.outcomes),
    };
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}
