import { existsSync } from 'node:fs';
import type { CrawlerKind } from '../job.js';
import { runCheerio } from './cheerio.js';
import type { CrawlDeps, CrawlFn } from './types.js';

export type { CrawlDeps, CrawlFn, CrawlSink, CrawlSummary, CrawledItem } from './types.js';

// The Playwright crawler is loaded only when a job asks for it: the slim image does not ship it,
// and importing @crawlee/browser-pool starts a local helper proxy that Cheerio jobs never need.
export function createCrawl(deps: CrawlDeps): CrawlFn {
  return async (spec, sink, signal) => {
    if (spec.crawler === 'playwright') {
      const { runPlaywright } = await import('./playwright.js');
      return runPlaywright(spec, deps, sink, signal);
    }
    return runCheerio(spec, deps, sink, signal);
  };
}

export async function detectCrawlers(restrictTo?: string[]): Promise<CrawlerKind[]> {
  const found: CrawlerKind[] = ['cheerio'];
  try {
    import.meta.resolve('@crawlee/playwright');
    const { firefox } = await import('playwright');
    const path = firefox.executablePath();
    if (path && existsSync(path)) found.push('playwright');
  } catch {
    // @crawlee/playwright or playwright is not installed (slim image).
  }
  return restrictTo ? found.filter((c) => restrictTo.includes(c)) : found;
}
