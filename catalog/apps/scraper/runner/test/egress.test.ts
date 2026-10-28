import { describe, expect, it } from 'vitest';
import { describeFailure, HttpStatusError } from '../src/crawl/common.js';
import { egressMessage, egressVerdictFromError, egressVerdictFromHeader, hostPort } from '../src/egress.js';

describe('egress verdicts', () => {
  it('reads the X-Sealed-Egress marker on http responses', () => {
    expect(egressVerdictFromHeader('blocked')).toBe('blocked');
    expect(egressVerdictFromHeader(['limited'])).toBe('limited');
    expect(egressVerdictFromHeader('auth-required')).toBe('blocked');
    expect(egressVerdictFromHeader(undefined)).toBeNull();
    expect(egressVerdictFromHeader('')).toBeNull();
  });

  it('recognises refused CONNECTs from got-scraping and Firefox', () => {
    expect(egressVerdictFromError(new Error('Proxy responded with 403 Forbidden: 0 bytes.'))).toBe('blocked');
    expect(egressVerdictFromError(new Error('Proxy responded with 407 Proxy Authentication Required'))).toBe('blocked');
    expect(egressVerdictFromError(new Error('Proxy responded with 429 Too Many Requests'))).toBe('limited');
    expect(egressVerdictFromError(new Error('page.goto: NS_ERROR_PROXY_FORBIDDEN'))).toBe('blocked');
    expect(egressVerdictFromError(new Error('page.goto: NS_ERROR_PROXY_TOO_MANY_REQUESTS'))).toBe('limited');
    expect(egressVerdictFromError(new Error('Proxy responded with 502 Bad Gateway'))).toBeNull();
    expect(egressVerdictFromError(new Error('ECONNRESET'))).toBeNull();
  });

  it('names the host:port to add', () => {
    expect(hostPort('https://shop.example/x')).toBe('shop.example:443');
    expect(hostPort('http://shop.example:8080/')).toBe('shop.example:8080');
    expect(egressMessage('blocked', 'http://a.example/')).toBe('blocked by sealed-egress: a.example:80 is not in egressAdditions.scraper');
    expect(egressMessage('limited', 'http://a.example/')).toBe('rate limited by sealed-egress');
  });

  it('describes failures without Crawlee retry notices', () => {
    expect(describeFailure('https://a.example/', new HttpStatusError('HTTP 404'))).toBe('HTTP 404');
    expect(describeFailure('https://a.example/', new Error('Detected a session error, rotating session... \nProxy responded with 403 Forbidden'))).toBe(
      'blocked by sealed-egress: a.example:443 is not in egressAdditions.scraper',
    );
    expect(describeFailure('https://a.example/', new Error('Detected a session error, rotating session... \nsocket hang up'))).toBe('socket hang up');
  });
});
