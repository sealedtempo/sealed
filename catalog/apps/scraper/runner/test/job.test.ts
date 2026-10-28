import { describe, expect, it } from 'vitest';
import { parseJobSpec, type FieldError } from '../src/job.js';

function errors(input: unknown, available?: ('cheerio' | 'playwright')[]): FieldError[] {
  const r = parseJobSpec(input, available);
  return r.ok ? [] : r.errors;
}

const fields = (input: unknown, available?: ('cheerio' | 'playwright')[]) => errors(input, available).map((e) => e.field);

describe('parseJobSpec', () => {
  it('fills defaults', () => {
    const r = parseJobSpec({ start_urls: ['https://example.com'] });
    expect(r).toEqual({
      ok: true,
      spec: {
        start_urls: ['https://example.com/'],
        max_pages: 100,
        crawler: 'cheerio',
        same_domain: true,
        extract: {},
        max_concurrency: 4,
        max_requests_per_minute: 60,
        respect_robots: true,
      },
    });
  });

  it('uses the lower default concurrency for playwright', () => {
    const r = parseJobSpec({ start_urls: ['https://example.com/'], crawler: 'playwright' });
    expect(r.ok && r.spec.max_concurrency).toBe(2);
  });

  it('accepts a full job and dedupes start URLs', () => {
    const r = parseJobSpec({
      start_urls: ['https://example.com/a', ' https://example.com/a ', 'https://example.org/'],
      max_pages: 10,
      crawler: 'cheerio',
      same_domain: false,
      extract: { title: 'h1', link: 'a.next@href' },
      max_concurrency: 8,
      max_requests_per_minute: 600,
      respect_robots: false,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.spec.start_urls).toEqual(['https://example.com/a', 'https://example.org/']);
    expect(r.spec.extract).toEqual({ title: 'h1', link: 'a.next@href' });
    expect(r.spec.respect_robots).toBe(false);
  });

  it('rejects non-objects and unknown keys', () => {
    expect(fields(null)).toEqual(['']);
    expect(fields([])).toEqual(['']);
    expect(fields({ start_urls: ['https://example.com/'], proxy: 'http://evil' })).toEqual(['proxy']);
  });

  it('validates start_urls', () => {
    expect(fields({})).toEqual(['start_urls']);
    expect(fields({ start_urls: [] })).toEqual(['start_urls']);
    expect(fields({ start_urls: 'https://example.com/' })).toEqual(['start_urls']);
    expect(fields({ start_urls: Array(101).fill('https://example.com/') })).toEqual(['start_urls']);
    expect(fields({ start_urls: ['https://example.com/', 42, 'http://169.254.169.254/', 'ftp://x.example/'] })).toEqual([
      'start_urls[1]',
      'start_urls[2]',
      'start_urls[3]',
    ]);
    expect(fields({ start_urls: ['https://example.com/' + 'a'.repeat(2048)] })).toEqual(['start_urls[0]']);
  });

  it('validates numbers and booleans', () => {
    const base = { start_urls: ['https://example.com/'] };
    expect(fields({ ...base, max_pages: 0 })).toEqual(['max_pages']);
    expect(fields({ ...base, max_pages: 10_001 })).toEqual(['max_pages']);
    expect(fields({ ...base, max_pages: 1.5 })).toEqual(['max_pages']);
    expect(fields({ ...base, max_pages: '10' })).toEqual(['max_pages']);
    expect(fields({ ...base, max_concurrency: 33 })).toEqual(['max_concurrency']);
    expect(fields({ ...base, crawler: 'playwright', max_concurrency: 5 })).toEqual(['max_concurrency']);
    expect(fields({ ...base, max_requests_per_minute: 0 })).toEqual(['max_requests_per_minute']);
    expect(fields({ ...base, max_requests_per_minute: 1201 })).toEqual(['max_requests_per_minute']);
    expect(fields({ ...base, same_domain: 'yes' })).toEqual(['same_domain']);
    expect(fields({ ...base, respect_robots: 0 })).toEqual(['respect_robots']);
  });

  it('validates the crawler against what the image ships', () => {
    const base = { start_urls: ['https://example.com/'] };
    expect(fields({ ...base, crawler: 'puppeteer' })).toEqual(['crawler']);
    expect(errors({ ...base, crawler: 'playwright' }, ['cheerio'])).toEqual([
      { field: 'crawler', message: 'playwright is not available in this image' },
    ]);
  });

  it('validates extract', () => {
    const base = { start_urls: ['https://example.com/'] };
    expect(fields({ ...base, extract: ['h1'] })).toEqual(['extract']);
    expect(fields({ ...base, extract: { '1bad': 'h1', 'has space': 'h1', ok: 'h1' } })).toEqual(['extract.1bad', 'extract.has space']);
    expect(fields({ ...base, extract: { url: 'a@href' } })).toEqual(['extract.url']);
    // A JSON body can carry "__proto__" as an ordinary key; it must be refused, not dropped.
    const proto = JSON.parse('{"__proto__": "h1", "constructor": "h2", "prototype": "h3", "b": "p"}') as unknown;
    expect(fields({ ...base, extract: proto })).toEqual(['extract.__proto__', 'extract.constructor', 'extract.prototype']);
    expect(fields({ ...base, extract: { a: '', b: 7, c: 'a[' } })).toEqual(['extract.a', 'extract.b', 'extract.c']);
    expect(fields({ ...base, extract: { a: 'p'.repeat(501) } })).toEqual(['extract.a']);
    const many = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`f${i}`, 'p']));
    expect(fields({ ...base, extract: many })).toEqual(['extract']);
  });
});
