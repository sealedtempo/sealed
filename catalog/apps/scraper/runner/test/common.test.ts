import { describe, expect, it } from 'vitest';
import { linkBaseFor, START_REQUEST } from '../src/crawl/common.js';

describe('linkBaseFor', () => {
  const start = { [START_REQUEST]: true };

  it('uses the redirect target of a start URL that changed host name', () => {
    expect(linkBaseFor({ url: 'https://example.com/', loadedUrl: 'https://www.example.com/', userData: start })).toBe('https://www.example.com/');
  });

  it('keeps Crawlee defaults otherwise', () => {
    expect(linkBaseFor({ url: 'https://example.com/', loadedUrl: 'https://example.com/home', userData: start })).toBeUndefined();
    expect(linkBaseFor({ url: 'https://example.com/a', loadedUrl: 'https://elsewhere.example/', userData: {} })).toBeUndefined();
    expect(linkBaseFor({ url: 'https://example.com/', userData: start })).toBeUndefined();
  });
});
