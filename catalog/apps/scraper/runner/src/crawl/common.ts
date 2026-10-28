import { Configuration, ProxyConfiguration, type EnqueueLinksOptions, type RequestOptions } from '@crawlee/core';
import { MemoryStorage } from '@crawlee/memory-storage';
import { extractFields, type ParsedPage } from '../extract.js';
import type { JobSpec } from '../job.js';
import { errorMessage } from '../log.js';
import { createProxyRobotsFetcher, RobotsPolicy } from '../robots.js';
import { checkTargetUrl } from '../url-policy.js';
import { egressMessage, egressVerdictFromError, type EgressVerdict } from '../egress.js';
import type { CrawlDeps, CrawlSink, CrawlSummary } from './types.js';

const withoutHash = (url: string) => url.replace(/#.*$/, '');

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

export function robotsPolicy(deps: CrawlDeps, sink: CrawlSink): RobotsPolicy {
  const fetcher = deps.robotsFetcher ?? createProxyRobotsFetcher({ proxyUrl: deps.proxyUrl, userAgent: deps.userAgent });
  return new RobotsPolicy(fetcher, deps.proxyUrl, (url, outcome, reason) => sink.robots(url, outcome, reason));
}

// Crawlee reports a skipped link once per page that links to it, and reports max_pages
// ("limit", "enqueueLimit") even for links that were already crawled. Report each skipped URL once,
// and leave max_pages out: the run's page cap is already part of its spec.
const LIMIT_REASONS = new Set(['limit', 'enqueueLimit']);
const MAX_TRACKED_SKIPS = 100_000;

// State one run's handlers share.
export interface RunState {
  // Where redirected start URLs landed. Links back there (for example "./") are the start page
  // again under the URL it was loaded from, which Crawlee does not know it already crawled; they
  // are dropped without a skip report.
  redirectedStarts: Set<string>;
}

export function newRunState(): RunState {
  return { redirectedStarts: new Set() };
}

export function skipReporter(sink: CrawlSink, state: RunState = newRunState()) {
  const seen = new Set<string>();
  return async ({ url, reason }: { url: string; reason: string }) => {
    if (LIMIT_REASONS.has(reason) || seen.has(url) || state.redirectedStarts.has(withoutHash(url))) return;
    if (seen.size < MAX_TRACKED_SKIPS) seen.add(url);
    await sink.skipped(url, reason);
  };
}

// Options shared by the Cheerio and Playwright crawlers.
export function sharedOptions(spec: JobSpec, deps: CrawlDeps, sink: CrawlSink, state: RunState) {
  return {
    proxyConfiguration: egressProxy(deps.proxyUrl),
    respectRobotsTxtFile: spec.respect_robots ? { userAgent: deps.robotsUserAgent } : false,
    maxRequestsPerCrawl: spec.max_pages,
    minConcurrency: 1,
    maxConcurrency: spec.max_concurrency,
    maxRequestsPerMinute: spec.max_requests_per_minute,
    // Retries are for network errors, timeouts and 5xx. An honest bot does not retry or rotate
    // sessions to get past 401, 403 or 429: with no blocked status codes, Crawlee hands those to
    // handlePage, which fails them without a retry. Egress refusals are not retried either.
    maxRequestRetries: 2,
    maxSessionRotations: 1,
    sessionPoolOptions: { blockedStatusCodes: [] },
    requestHandlerTimeoutSecs: 60,
    retryOnBlocked: false,
    onSkippedRequest: skipReporter(sink, state),
    errorHandler: ({ request }: { request: { noRetry: boolean } }, error: Error) => {
      if (egressVerdictFromError(error) === 'blocked') request.noRetry = true;
    },
    failedRequestHandler: async ({ request }: { request: { url: string } }, error: Error) => {
      await sink.failed(request.url, describeFailure(request.url, error));
    },
  };
}

export function describeFailure(url: string, error: Error): string {
  if (error instanceof HttpStatusError) return error.message;
  const verdict = egressVerdictFromError(error);
  if (verdict) return egressMessage(verdict, url);
  // Crawlee prefixes session errors with its own retry notice.
  return errorMessage(error).replace(/^Detected a session error, rotating session\.\.\.\s*/, '');
}

// `skip` holds pages already crawled under another URL (see pageHandler).
export function enqueueOptions(spec: JobSpec, baseUrl?: string, skip?: ReadonlySet<string>): EnqueueLinksOptions {
  return {
    strategy: spec.same_domain ? 'same-hostname' : 'all',
    transformRequestFunction: (req: RequestOptions) => (checkTargetUrl(req.url) || skip?.has(withoutHash(req.url)) ? false : req),
    ...(baseUrl ? { baseUrl } : {}),
  };
}

// Marks the requests made from start_urls.
export const START_REQUEST = 'sealedStart';

// Crawlee keeps filtering same-hostname links against the original URL after a redirect. For a
// start URL that redirects to another host name (example.com -> www.example.com) the redirect
// target is the site the customer meant, so its links are filtered against that instead. Redirects
// of later pages never widen the crawl, and sealed-egress still decides what is reachable.
export function linkBaseFor(request: { url: string; loadedUrl?: string; userData?: Record<string, unknown> }): string | undefined {
  if (!request.userData?.[START_REQUEST] || !request.loadedUrl) return undefined;
  try {
    return new URL(request.loadedUrl).hostname !== new URL(request.url).hostname ? request.loadedUrl : undefined;
  } catch {
    return undefined;
  }
}

// A page failure whose message is ready to show the user.
export class HttpStatusError extends Error {}

interface PageContext {
  request: { url: string; loadedUrl?: string; noRetry: boolean; userData?: Record<string, unknown> };
  enqueueLinks: (options: EnqueueLinksOptions) => Promise<unknown>;
}

export interface PageResponse {
  statusCode: number | null;
  // Set when sealed-egress itself answered (http targets), see egress.ts.
  egress: EgressVerdict | null;
}

// What a final response means when it is not a usable page: a 4xx or 5xx status is a failure,
// retried only for 5xx. An egress refusal is not retried; an egress rate limit is.
export function responseFailure(url: string, { statusCode, egress }: PageResponse): { error: HttpStatusError; retry: boolean } | null {
  if (egress) return { error: new HttpStatusError(egressMessage(egress, url)), retry: egress === 'limited' };
  if (statusCode !== null && statusCode >= 400) return { error: new HttpStatusError(`HTTP ${statusCode}`), retry: statusCode >= 500 };
  return null;
}

export function throwOnFailedResponse(request: { url: string; noRetry: boolean }, response: PageResponse): void {
  const failure = responseFailure(request.url, response);
  if (!failure) return;
  request.noRetry = !failure.retry;
  throw failure.error;
}

export type PageHandler = (ctx: PageContext, response: PageResponse, $: ParsedPage | undefined) => Promise<void>;

// One per run. Successful pages only (see responseFailure); stores the item after enqueueing its
// links.
export function pageHandler(spec: JobSpec, sink: CrawlSink, { redirectedStarts }: RunState): PageHandler {
  return async (ctx, response, $) => {
    throwOnFailedResponse(ctx.request, response);
    if (!$) {
      ctx.request.noRetry = true;
      throw new HttpStatusError('response is not HTML');
    }
    const url = ctx.request.loadedUrl ?? ctx.request.url;
    const base = linkBaseFor(ctx.request);
    if (base) redirectedStarts.add(withoutHash(base));
    await ctx.enqueueLinks(enqueueOptions(spec, base, redirectedStarts));
    await sink.item({ url, statusCode: response.statusCode, data: extractFields($, spec.extract, url) });
  };
}

interface Stoppable {
  stop(reason?: string): void;
  run(requests: { url: string; userData: Record<string, unknown> }[]): Promise<{ requestsFinished: number; requestsFailed: number }>;
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
    const stats = await crawler.run(spec.start_urls.map((url) => ({ url, userData: { [START_REQUEST]: true } })));
    return {
      requestsFinished: stats.requestsFinished,
      requestsFailed: stats.requestsFailed,
      robots: Object.fromEntries(robots.outcomes),
    };
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}
