import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { CrawlDeps, CrawlSink, CrawledItem } from '../../src/crawl/types.js';
import { parseJobSpec, type JobSpec } from '../../src/job.js';

export const FIXTURES = resolve(import.meta.dirname, '../../../fixtures');
export const SITE = resolve(FIXTURES, 'site');
export const FIXTURE_HOST = 'fixture.test';

export interface ExpectedItems {
  items: Array<{ path: string; name: string; sku: string; price: string; category: string; description: string }>;
  skipped_robots: string[];
  not_visited: string[];
}

export const expected: ExpectedItems = JSON.parse(readFileSync(resolve(FIXTURES, 'expected-items.json'), 'utf8'));

// The A6 job from fixtures/a6-job.json, pointed at a test host and sped up.
export function a6Job(overrides: Record<string, unknown> = {}, host = FIXTURE_HOST): JobSpec {
  const raw = JSON.parse(readFileSync(resolve(FIXTURES, 'a6-job.json'), 'utf8')) as Record<string, unknown>;
  const job = {
    ...raw,
    start_urls: [`http://${host}/`],
    max_requests_per_minute: 1200,
    ...overrides,
  };
  const parsed = parseJobSpec(job);
  if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors));
  return parsed.spec;
}

export function testDeps(proxyUrl: string): CrawlDeps {
  return { proxyUrl, userAgent: 'SealedScraper/1.0 (+test)', robotsUserAgent: 'SealedScraper', memoryMbytes: 1024 };
}

export interface MemorySink {
  sink: CrawlSink;
  items: CrawledItem[];
  failed: { url: string; error: string }[];
  skipped: { url: string; reason: string }[];
}

export function memorySink(onItem?: (item: CrawledItem) => void): MemorySink {
  const out: MemorySink = {
    items: [],
    failed: [],
    skipped: [],
    sink: {
      item: async (item) => {
        out.items.push(item);
        onItem?.(item);
      },
      failed: async (url, error) => {
        out.failed.push({ url, error });
      },
      skipped: async (url, reason) => {
        out.skipped.push({ url, reason });
      },
    },
  };
  return out;
}
