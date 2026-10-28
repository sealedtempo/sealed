import { RobotsTxtFile } from '@crawlee/utils';
import { gotScraping } from 'got-scraping';

// Crawlee 3.18.2 fetches robots.txt without the proxy, with TLS verification off, and treats every
// failure except 404 as "allow" (got-scraping does not throw on 5xx). This module replaces that with
// RFC 9309 semantics, fetched through sealed-egress:
//   2xx            -> parse the body (first 500 KiB)
//   4xx            -> unavailable: allow everything
//   > 5 redirects  -> unavailable: allow everything (RFC 9309 2.3.1.2)
//   5xx, other     -> unreachable: disallow everything
//   network error  -> unreachable: disallow everything

export interface RobotsFetchResult {
  status: number;
  body: string;
}

// Resolves with the final response after redirects; rejects on network errors and timeouts.
export type RobotsFetcher = (robotsUrl: string) => Promise<RobotsFetchResult>;

export type RobotsOutcome = 'parsed' | 'allow-all' | 'deny-all';

export const DENY_ALL = 'User-agent: *\nDisallow: /\n';
export const MAX_ROBOTS_BYTES = 500 * 1024;
export const MAX_ROBOTS_REDIRECTS = 5;

export class RobotsRedirectLimitError extends Error {}

export function interpretRobots(result: RobotsFetchResult | Error): { outcome: RobotsOutcome; body: string } {
  if (result instanceof RobotsRedirectLimitError) return { outcome: 'allow-all', body: '' };
  if (result instanceof Error) return { outcome: 'deny-all', body: DENY_ALL };
  const { status, body } = result;
  if (status >= 200 && status < 300) return { outcome: 'parsed', body: body.slice(0, MAX_ROBOTS_BYTES) };
  if ((status >= 300 && status < 400) || (status >= 400 && status < 500)) return { outcome: 'allow-all', body: '' };
  return { outcome: 'deny-all', body: DENY_ALL };
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
        .then(({ outcome, body }) => {
          this.outcomes.set(robotsUrl, outcome);
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
      let size = 0;
      const chunks: Buffer[] = [];
      const finish = () => resolve({ status, body: Buffer.concat(chunks).toString('utf8') });
      stream.on('response', (res: { statusCode: number }) => {
        status = res.statusCode;
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
