import { describe, expect, it } from 'vitest';
import { ConfigError, DEFAULT_USER_AGENT, loadConfig, resolveProxyUrl } from '../src/config.js';
import { dropSecrets, hardenEnv } from '../src/env-guard.js';

const base = { DATABASE_URL: 'postgres://scraper@scraper-db:5432/scraper', HTTP_PROXY: 'http://172.30.0.2:3128' };

describe('loadConfig', () => {
  it('reads the in-VM defaults', () => {
    const c = loadConfig(base, () => '');
    expect(c).toMatchObject({
      port: 8080,
      host: '0.0.0.0',
      proxyUrl: 'http://172.30.0.2:3128',
      agentUrl: 'http://sealed-agent:7070',
      maxRuns: 2,
      meterFlushMs: 5000,
      meterMaxBatch: 50,
      userAgent: DEFAULT_USER_AGENT,
      robotsUserAgent: 'SealedScraper',
      dbPassword: undefined,
      maxPageBytes: 8 * 1024 * 1024,
    });
  });

  it('requires DATABASE_URL', () => {
    expect(() => loadConfig({ HTTP_PROXY: base.HTTP_PROXY })).toThrow(ConfigError);
  });

  it('refuses to run without the egress proxy unless explicitly in development', () => {
    expect(() => loadConfig({ DATABASE_URL: base.DATABASE_URL })).toThrow(/HTTP_PROXY/);
    expect(loadConfig({ DATABASE_URL: base.DATABASE_URL, SCRAPER_ALLOW_NO_PROXY: '1' }).proxyUrl).toBeUndefined();
  });

  it('rejects malformed proxy URLs', () => {
    expect(() => loadConfig({ ...base, HTTP_PROXY: 'socks5://x:1080' })).toThrow(/http or https/);
    expect(() => loadConfig({ ...base, HTTP_PROXY: 'nope' })).toThrow(/valid URL/);
  });

  it('reads the database password from the env or from the secret file', () => {
    expect(loadConfig({ ...base, SCRAPER_DB_PASSWORD: 's3cret' }).dbPassword).toBe('s3cret');
    const read = (p: string) => (p === '/run/sealed/secrets/scraper/SCRAPER_DB_PASSWORD' ? 'from-file\n' : '');
    expect(loadConfig({ ...base, SCRAPER_DB_PASSWORD_FILE: '/run/sealed/secrets/scraper/SCRAPER_DB_PASSWORD' }, read).dbPassword).toBe(
      'from-file',
    );
    const missing = () => {
      throw new Error('ENOENT');
    };
    expect(() => loadConfig({ ...base, SCRAPER_DB_PASSWORD_FILE: '/nope' }, missing)).toThrow(/cannot be read/);
  });

  it('validates numbers', () => {
    expect(() => loadConfig({ ...base, PORT: '0' })).toThrow(/PORT/);
    expect(() => loadConfig({ ...base, SCRAPER_MAX_RUNS: '9' })).toThrow(/SCRAPER_MAX_RUNS/);
    expect(loadConfig({ ...base, SCRAPER_MAX_RUNS: '4' }).maxRuns).toBe(4);
    expect(loadConfig({ ...base, SCRAPER_MAX_PAGE_BYTES: '1048576' }).maxPageBytes).toBe(1048576);
    expect(() => loadConfig({ ...base, SCRAPER_MAX_PAGE_BYTES: '1000' })).toThrow(/SCRAPER_MAX_PAGE_BYTES/);
  });

  it('can turn metering off for local development', () => {
    expect(loadConfig({ ...base, SCRAPER_METERING: 'off' }).agentUrl).toBeUndefined();
    expect(() => loadConfig({ ...base, SCRAPER_METERING: 'maybe' })).toThrow();
  });

  it('allows Caddy and loopback by default and reads SCRAPER_ALLOWED_CLIENTS', () => {
    expect(loadConfig(base).allowedClients.entries).toEqual(['172.30.0.4', '127.0.0.1', '::1']);
    const custom = loadConfig({ ...base, SCRAPER_ALLOWED_CLIENTS: '172.30.0.4, 172.30.0.20' }).allowedClients;
    expect(custom.allows('172.30.0.20')).toBe(true);
    expect(custom.allows('127.0.0.1')).toBe(false);
    expect(() => loadConfig({ ...base, SCRAPER_ALLOWED_CLIENTS: 'caddy' })).toThrow(/SCRAPER_ALLOWED_CLIENTS caddy is not an IP/);
  });

  it('can restrict crawlers', () => {
    expect(loadConfig({ ...base, SCRAPER_CRAWLERS: 'cheerio, playwright' }).crawlers).toEqual(['cheerio', 'playwright']);
  });
});

describe('resolveProxyUrl', () => {
  it('prefers an explicit override, then HTTP_PROXY', () => {
    expect(resolveProxyUrl({ HTTPS_PROXY: 'http://b:1', HTTP_PROXY: 'http://a:1' })).toBe('http://a:1');
    expect(resolveProxyUrl({ SCRAPER_PROXY_URL: 'http://c:1', HTTP_PROXY: 'http://a:1' })).toBe('http://c:1');
    expect(resolveProxyUrl({ https_proxy: 'http://d:1' })).toBe('http://d:1');
    expect(resolveProxyUrl({})).toBeUndefined();
  });
});

describe('dropSecrets', () => {
  it('removes the database password variables after the config has read them', () => {
    const env: NodeJS.ProcessEnv = { ...base, SCRAPER_DB_PASSWORD: 's3cret', SCRAPER_DB_PASSWORD_FILE: '/run/x', KEEP: 'me' };
    expect(loadConfig(env).dbPassword).toBe('s3cret');
    expect(dropSecrets(env).sort()).toEqual(['SCRAPER_DB_PASSWORD', 'SCRAPER_DB_PASSWORD_FILE']);
    expect(env).toEqual({ ...base, KEEP: 'me' });
    expect(dropSecrets(env)).toEqual([]);
  });
});

describe('hardenEnv', () => {
  it('forces memory-only Crawlee storage and strips sandbox and proxy-bypass switches', () => {
    const env: NodeJS.ProcessEnv = {
      CRAWLEE_PERSIST_STORAGE: 'true',
      CRAWLEE_DISABLE_BROWSER_SANDBOX: '1',
      MOZ_DISABLE_CONTENT_SANDBOX: '1',
      PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK: '1',
      KEEP: 'me',
    };
    const changed = hardenEnv(env);
    expect(env).toEqual({ CRAWLEE_PERSIST_STORAGE: 'false', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1', KEEP: 'me' });
    expect(changed).toContain('MOZ_DISABLE_CONTENT_SANDBOX');
    expect(hardenEnv(env)).toEqual([]);
  });
});
