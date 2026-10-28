import { selectorError } from './extract.js';
import { checkTargetUrl } from './url-policy.js';

export const CRAWLERS = ['cheerio', 'playwright'] as const;
export type CrawlerKind = (typeof CRAWLERS)[number];

export interface JobSpec {
  start_urls: string[];
  max_pages: number;
  crawler: CrawlerKind;
  same_domain: boolean;
  extract: Record<string, string>;
  max_concurrency: number;
  max_requests_per_minute: number;
  respect_robots: boolean;
}

export interface FieldError {
  field: string;
  message: string;
}

export type ParseResult = { ok: true; spec: JobSpec } | { ok: false; errors: FieldError[] };

export const LIMITS = {
  startUrls: 100,
  urlLength: 2048,
  maxPages: 10_000,
  fields: 50,
  selectorLength: 500,
  requestsPerMinute: 1200,
  concurrency: { cheerio: 32, playwright: 4 } as Record<CrawlerKind, number>,
} as const;

const DEFAULT_CONCURRENCY: Record<CrawlerKind, number> = { cheerio: 4, playwright: 2 };
const DEFAULT_REQUESTS_PER_MINUTE = 60;
const DEFAULT_MAX_PAGES = 100;
const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
// Columns the exports add themselves.
export const RESERVED_FIELDS = new Set(['url']);
const KEYS = new Set([
  'start_urls',
  'max_pages',
  'crawler',
  'same_domain',
  'extract',
  'max_concurrency',
  'max_requests_per_minute',
  'respect_robots',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function intField(
  input: Record<string, unknown>,
  name: string,
  fallback: number,
  min: number,
  max: number,
  errors: FieldError[],
): number {
  const value = input[name];
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    errors.push({ field: name, message: `must be an integer between ${min} and ${max}` });
    return fallback;
  }
  return value;
}

function boolField(input: Record<string, unknown>, name: string, fallback: boolean, errors: FieldError[]): boolean {
  const value = input[name];
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') {
    errors.push({ field: name, message: 'must be true or false' });
    return fallback;
  }
  return value;
}

function parseStartUrls(value: unknown, errors: FieldError[]): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    errors.push({ field: 'start_urls', message: 'must be a non-empty list of URLs' });
    return [];
  }
  if (value.length > LIMITS.startUrls) {
    errors.push({ field: 'start_urls', message: `must have at most ${LIMITS.startUrls} URLs` });
    return [];
  }
  const urls: string[] = [];
  value.forEach((entry, i) => {
    const field = `start_urls[${i}]`;
    if (typeof entry !== 'string' || entry.trim() === '') {
      errors.push({ field, message: 'must be a URL string' });
      return;
    }
    const trimmed = entry.trim();
    if (trimmed.length > LIMITS.urlLength) {
      errors.push({ field, message: `must be at most ${LIMITS.urlLength} characters` });
      return;
    }
    const problem = checkTargetUrl(trimmed);
    if (problem) {
      errors.push({ field, message: problem });
      return;
    }
    const normalized = new URL(trimmed).toString();
    if (!urls.includes(normalized)) urls.push(normalized);
  });
  return urls;
}

function parseExtract(value: unknown, errors: FieldError[]): Record<string, string> {
  if (value === undefined) return {};
  if (!isRecord(value)) {
    errors.push({ field: 'extract', message: 'must be an object of field name to CSS selector' });
    return {};
  }
  const entries = Object.entries(value);
  if (entries.length > LIMITS.fields) {
    errors.push({ field: 'extract', message: `must have at most ${LIMITS.fields} fields` });
    return {};
  }
  const out: Record<string, string> = {};
  for (const [name, selector] of entries) {
    const field = `extract.${name}`;
    if (!FIELD_NAME.test(name)) {
      errors.push({ field, message: 'field names use letters, digits and underscores, start with a letter or underscore, max 64' });
      continue;
    }
    if (RESERVED_FIELDS.has(name)) {
      errors.push({ field, message: 'is reserved' });
      continue;
    }
    if (typeof selector !== 'string' || selector.trim() === '') {
      errors.push({ field, message: 'must be a CSS selector string' });
      continue;
    }
    if (selector.length > LIMITS.selectorLength) {
      errors.push({ field, message: `must be at most ${LIMITS.selectorLength} characters` });
      continue;
    }
    const problem = selectorError(selector);
    if (problem) {
      errors.push({ field, message: problem });
      continue;
    }
    out[name] = selector.trim();
  }
  return out;
}

export function parseJobSpec(input: unknown, available: readonly CrawlerKind[] = CRAWLERS): ParseResult {
  const errors: FieldError[] = [];
  if (!isRecord(input)) {
    return { ok: false, errors: [{ field: '', message: 'body must be a JSON object' }] };
  }
  for (const key of Object.keys(input)) {
    if (!KEYS.has(key)) errors.push({ field: key, message: 'is not a known job field' });
  }

  let crawler: CrawlerKind = 'cheerio';
  if (input.crawler !== undefined) {
    if (!CRAWLERS.includes(input.crawler as CrawlerKind)) {
      errors.push({ field: 'crawler', message: `must be one of ${CRAWLERS.join(', ')}` });
    } else if (!available.includes(input.crawler as CrawlerKind)) {
      errors.push({ field: 'crawler', message: `${String(input.crawler)} is not available in this image` });
    } else {
      crawler = input.crawler as CrawlerKind;
    }
  }

  const spec: JobSpec = {
    start_urls: parseStartUrls(input.start_urls, errors),
    max_pages: intField(input, 'max_pages', DEFAULT_MAX_PAGES, 1, LIMITS.maxPages, errors),
    crawler,
    same_domain: boolField(input, 'same_domain', true, errors),
    extract: parseExtract(input.extract, errors),
    max_concurrency: intField(input, 'max_concurrency', DEFAULT_CONCURRENCY[crawler], 1, LIMITS.concurrency[crawler], errors),
    max_requests_per_minute: intField(
      input,
      'max_requests_per_minute',
      DEFAULT_REQUESTS_PER_MINUTE,
      1,
      LIMITS.requestsPerMinute,
      errors,
    ),
    respect_robots: boolField(input, 'respect_robots', true, errors),
  };
  return errors.length > 0 ? { ok: false, errors } : { ok: true, spec };
}
