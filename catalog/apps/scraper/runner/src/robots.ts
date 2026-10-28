import { RobotsTxtFile } from '@crawlee/utils';
import { gotScraping } from 'got-scraping';
import { EGRESS_HEADER, egressVerdictFromError } from './egress.js';

// Crawlee 3.18.2 fetches robots.txt without the proxy, with TLS verification off, and treats every
// failure except 404 as "allow" (got-scraping does not throw on 5xx). This module replaces that with
// RFC 9309 semantics, fetched through sealed-egress:
//   2xx                     -> parse the body (first 500 KiB)
//   4xx except 429          -> unavailable: allow everything
//   > 5 redirects           -> unavailable: allow everything (RFC 9309 2.3.1.2)
//   429, 5xx, other         -> unreachable: disallow everything
//   network error, timeout  -> unreachable: disallow everything
//   refused by sealed-egress (a failed CONNECT, or a response marked X-Sealed-Egress) -> unreachable
// Each outcome is reported with its reason, so a run can show why a site was not crawled.

export interface RobotsFetchResult {
  status: number;
  body: string;
  // The X-Sealed-Egress marker: set when sealed-egress itself answered (http targets).
  egress?: string | null;
}

// Resolves with the final response after redirects; rejects on network errors and timeouts.
export type RobotsFetcher = (robotsUrl: string) => Promise<RobotsFetchResult>;

export type RobotsOutcome = 'parsed' | 'allow-all' | 'deny-all';

export const DENY_ALL = 'User-agent: *\nDisallow: /\n';
export const MAX_ROBOTS_BYTES = 500 * 1024;
export const MAX_ROBOTS_REDIRECTS = 5;

export class RobotsRedirectLimitError extends Error {}

export interface RobotsDecision {
  outcome: RobotsOutcome;
  body: string;
  reason: string;
}

export type RobotsOutcomeListener = (robotsUrl: string, outcome: RobotsOutcome, reason: string) => Promise<void> | void;

const firstLine = (text: string) => (text.split('\n')[0] ?? '').trim().slice(0, 200);

export function interpretRobots(result: RobotsFetchResult | Error): RobotsDecision {
  const allow = (reason: string): RobotsDecision => ({ outcome: 'allow-all', body: '', reason });
  const deny = (reason: string): RobotsDecision => ({ outcome: 'deny-all', body: DENY_ALL, reason });
  if (result instanceof RobotsRedirectLimitError) return allow(`unavailable: more than ${MAX_ROBOTS_REDIRECTS} redirects`);
  if (result instanceof Error) {
    if (egressVerdictFromError(result)) return deny(`unreachable: refused by sealed-egress, add the host to egressAdditions.scraper`);
    return deny(`unreachable: ${firstLine(result.message) || result.name}`);
  }
  const { status, body, egress } = result;
  if (egress) return deny(`unreachable: refused by sealed-egress (${egress}), add the host to egressAdditions.scraper`);
  if (status >= 200 && status < 300) return { outcome: 'parsed', body: body.slice(0, MAX_ROBOTS_BYTES), reason: `HTTP ${status}` };
  if (status === 429) return deny('unreachable: HTTP 429');
  if (status >= 300 && status < 500) return allow(`unavailable: HTTP ${status}`);
  return deny(`unreachable: HTTP ${status}`);
}

export function robotsUrlFor(url: string): string {
  return `${new URL(url).origin}/robots.txt`;
}

export class RobotsPolicy {
  private readonly cache = new Map<string, Promise<RobotsTxtFile>>();
  readonly outcomes = new Map<string, RobotsOutcome>();

  constructor(
    private readonly fetcher: RobotsFetcher,
    private readonly proxyUrl?: string,
    private readonly onOutcome?: RobotsOutcomeListener,
  ) {}

  forUrl(url: string): Promise<RobotsTxtFile> {
    const robotsUrl = robotsUrlFor(url);
    let pending = this.cache.get(robotsUrl);
    if (!pending) {
      pending = this.fetcher(robotsUrl)
        .then(
          (res) => interpretRobots(res),
          (err: unknown) => interpretRobots(err instanceof Error ? err : new Error(String(err))),
        )
        .then(async ({ outcome, body, reason }) => {
          this.outcomes.set(robotsUrl, outcome);
          try {
            await this.onOutcome?.(robotsUrl, outcome, reason);
          } catch {
            // Reporting is best effort; the decision itself stands.
          }
          return RobotsTxtFile.from(robotsUrl, body, this.proxyUrl);
        });
      this.cache.set(robotsUrl, pending);
    }
    return pending;
  }

  async isAllowed(url: string, userAgent: string): Promise<boolean> {
    return (await this.forUrl(url)).isAllowed(url, userAgent);
  }
}

export interface ProxyRobotsFetcherOptions {
  proxyUrl: string | undefined;
  userAgent: string;
  timeoutMs?: number;
}

export function createProxyRobotsFetcher({ proxyUrl, userAgent, timeoutMs = 15_000 }: ProxyRobotsFetcherOptions): RobotsFetcher {
  return async (robotsUrl) => {
    const stream = await Promise.resolve(
      gotScraping({
        url: robotsUrl,
        method: 'GET',
        proxyUrl,
        isStream: true,
        throwHttpErrors: false,
        followRedirect: true,
        maxRedirects: MAX_ROBOTS_REDIRECTS,
        retry: { limit: 0 },
        timeout: { request: timeoutMs },
        https: { rejectUnauthorized: true },
        useHeaderGenerator: false,
        headers: { 'user-agent': userAgent, accept: 'text/plain,*/*;q=0.5' },
      }),
    );
    return new Promise<RobotsFetchResult>((resolve, reject) => {
      let status = 0;
      let egress: string | null = null;
      let size = 0;
      const chunks: Buffer[] = [];
      const finish = () => resolve({ status, body: Buffer.concat(chunks).toString('utf8'), egress });
      stream.on('response', (res: { statusCode: number; headers: Record<string, string | string[] | undefined> }) => {
        status = res.statusCode;
        const marker = res.headers[EGRESS_HEADER];
        egress = (Array.isArray(marker) ? marker[0] : marker) ?? null;
      });
      stream.on('data', (chunk: Buffer) => {
        if (size >= MAX_ROBOTS_BYTES) return;
        const room = MAX_ROBOTS_BYTES - size;
        chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
        size += Math.min(chunk.length, room);
        if (size >= MAX_ROBOTS_BYTES) {
          stream.destroy();
          finish();
        }
      });
      stream.on('end', finish);
      stream.on('error', (err: Error) => {
        if (size >= MAX_ROBOTS_BYTES) return;
        reject(err.name === 'MaxRedirectsError' ? new RobotsRedirectLimitError(err.message) : err);
      });
    });
  };
}
