import { describe, expect, it } from 'vitest';
import { formToJob, readForm } from '../src/http/form.js';
import { parseJobSpec } from '../src/job.js';

describe('UI form', () => {
  it('reads checkboxes as booleans and keeps text fields', () => {
    const form = readForm({ start_urls: 'https://a.test/', same_domain: 'on', max_pages: '5' });
    expect(form).toMatchObject({ start_urls: 'https://a.test/', same_domain: true, respect_robots: false, crawler: 'cheerio', max_pages: '5' });
  });

  it('turns lines into start URLs and name = selector fields', () => {
    const { job, errors } = formToJob(
      readForm({
        start_urls: ' https://a.test/ \r\n\r\nhttps://b.test/x\n# comment\n',
        extract: 'title = h1.title\nlink=a.next@href\n  price =  span[data-x="a=b"]  \n',
        max_pages: '10',
        max_concurrency: '',
        max_requests_per_minute: '30',
        crawler: 'cheerio',
        same_domain: 'on',
        respect_robots: 'on',
      }),
    );
    expect(errors).toEqual([]);
    expect(job).toEqual({
      start_urls: ['https://a.test/', 'https://b.test/x'],
      extract: { title: 'h1.title', link: 'a.next@href', price: 'span[data-x="a=b"]' },
      max_pages: 10,
      max_requests_per_minute: 30,
      crawler: 'cheerio',
      same_domain: true,
      respect_robots: true,
    });
    expect(parseJobSpec(job).ok).toBe(true);
  });

  it('reports malformed field lines and passes bad numbers through to validation', () => {
    const { job, errors } = formToJob(readForm({ start_urls: 'https://a.test/', extract: 'just-a-selector\n= h1', max_pages: 'ten' }));
    expect(errors).toEqual([
      { field: 'extract', message: 'line 1 must look like name = selector' },
      { field: 'extract', message: 'line 2 must look like name = selector' },
    ]);
    const parsed = parseJobSpec(job);
    expect(parsed.ok ? [] : parsed.errors.map((e) => e.field)).toEqual(['max_pages']);
  });
});
