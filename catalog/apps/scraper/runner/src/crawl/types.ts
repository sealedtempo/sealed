import type { ItemData } from '../extract.js';
import type { JobSpec } from '../job.js';
import type { RobotsFetcher, RobotsOutcome } from '../robots.js';

export interface CrawledItem {
  url: string;
  statusCode: number | null;
  data: ItemData;
}

// Where a crawl reports its results. Implementations persist them; the crawler never buffers items.
export interface CrawlSink {
  item(item: CrawledItem): Promise<void>;
  failed(url: string, error: string): Promise<void>;
  skipped(url: string, reason: string): Promise<void>;
}

export interface CrawlDeps {
  // sealed-egress. Undefined only in local development (SCRAPER_ALLOW_NO_PROXY=1).
  proxyUrl: string | undefined;
  userAgent: string;
  robotsUserAgent: string;
  memoryMbytes: number;
  robotsFetcher?: RobotsFetcher;
}

export interface CrawlSummary {
  requestsFinished: number;
  requestsFailed: number;
  robots: Record<string, RobotsOutcome>;
}

export type CrawlFn = (spec: JobSpec, sink: CrawlSink, signal: AbortSignal) => Promise<CrawlSummary>;
