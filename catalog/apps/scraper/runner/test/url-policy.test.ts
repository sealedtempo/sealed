import { describe, expect, it } from 'vitest';
import { checkTargetUrl } from '../src/url-policy.js';

describe('checkTargetUrl', () => {
  it.each([
    'https://example.com/',
    'http://shop.example.co.uk/path?q=1',
    'https://93.184.215.14/',
    'https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/',
    'http://fixture.test:8080/',
  ])('allows public targets: %s', (url) => {
    expect(checkTargetUrl(url)).toBeNull();
  });

  it.each([
    ['ftp://example.com/', 'http or https'],
    ['file:///etc/passwd', 'http or https'],
    ['https://user:pw@example.com/', 'credentials'],
    ['http://localhost:7070/', 'local or internal'],
    ['http://app.localhost/', 'local or internal'],
    ['http://metadata.google.internal/computeMetadata/v1/', 'local or internal'],
    ['http://printer.local/', 'local or internal'],
    ['http://sealed-agent:7070/v1/usage-events', 'fully qualified'],
    ['http://scraper-db:5432/', 'fully qualified'],
    ['http://127.0.0.1/', 'private'],
    ['http://2130706433/', 'private'],
    ['http://0x7f.1/', 'private'],
    ['http://10.1.2.3/', 'private'],
    ['http://172.30.0.3:7070/', 'private'],
    ['http://192.168.1.1/', 'private'],
    ['http://169.254.169.254/latest/meta-data/', 'private'],
    ['http://100.64.0.1/', 'private'],
    ['http://0.0.0.0/', 'private'],
    ['http://[::1]/', 'private'],
    ['http://[fe80::1]/', 'private'],
    ['http://[fd00::1]/', 'private'],
    ['http://[::ffff:127.0.0.1]/', 'private'],
    ['not a url', 'valid URL'],
  ])('refuses %s', (url, reason) => {
    expect(checkTargetUrl(url)).toContain(reason);
  });
});
