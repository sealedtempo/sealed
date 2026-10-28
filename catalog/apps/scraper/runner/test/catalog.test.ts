import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { load } from 'cheerio';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { extractFields } from '../src/extract.js';
import { parseJobSpec } from '../src/job.js';
import { caddySite, compose, envexecSecrets, findComposer, lint, secretMounts, type Composed, type Composer } from './helpers/composer.js';
import { expected, FIXTURES, SITE } from './helpers/fixture.js';

// Checks of the catalog package. The catalog rules (manifest schema, the fragment rules of
// docs/INTERFACES.md section 14, the egress policy, licenses) are checked only by the real
// composer, so there is no copy of them here; these tests add what is specific to the scraper,
// plus the Dockerfiles and the fixture site.

const APP = resolve(import.meta.dirname, '../..');
const REPO = resolve(APP, '../../..');
const read = (p: string) => readFileSync(resolve(APP, p), 'utf8');
const manifest = parse(read('manifest.yaml')) as Record<string, any>;
const fragment = parse(read('compose.fragment.yaml')) as { services: Record<string, Record<string, any>>; volumes: Record<string, unknown> };
const egress = parse(read('egress.yaml')) as Record<string, unknown>;
const runnerPkg = JSON.parse(readFileSync(resolve(APP, 'runner/package.json'), 'utf8')) as Record<string, any>;

describe('manifest.yaml', () => {
  it('describes the scraper as spec 6.3 asks', () => {
    expect(manifest).toMatchObject({
      id: 'scraper',
      primary_service: 'scraper-runner',
      metering: { unit: 'pages', source: 'callback' },
      routes: [{ name: 'scraper', service: 'scraper-runner', internal_port: 8080, auth: 'gate' }],
      healthcheck: { service: 'scraper-runner', http: '/healthz', port: 8080 },
      upstream: { license_spdx: 'Apache-2.0', version: runnerPkg.version },
    });
    expect(runnerPkg.license).toBe('Apache-2.0');
    expect(Object.keys(manifest.telemetry_off_env).length).toBeGreaterThan(0);
  });

  it('pins every image by digest', () => {
    for (const img of manifest.images) expect(img.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    const pg = manifest.images.find((i: { name: string }) => i.name === 'postgres');
    expect(pg).toMatchObject({
      source: 'docker.io/library/postgres:17.11-alpine',
      digest: 'sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b',
    });
  });
});

describe('egress.yaml', () => {
  it('allows nothing by default and only customer additions', () => {
    expect(egress).toMatchObject({ version: 1, default_allow: [], customer_additions_allowed: true });
    expect(typeof egress.notes).toBe('string');
  });
});

describe('compose.fragment.yaml', () => {
  const services = Object.entries(fragment.services);

  it('has scraper-runner and scraper-db', () => {
    expect(Object.keys(fragment.services).sort()).toEqual(['scraper-db', 'scraper-runner']);
  });

  it('lists the database password for exactly the two services that read it, never in a URL', () => {
    // Each service gets bind mounts of exactly the secret files it lists (integration brief item 5).
    expect(fragment.services['scraper-runner']!['x-sealed-secrets']).toEqual(['SCRAPER_DB_PASSWORD']);
    expect(fragment.services['scraper-db']!['x-sealed-secrets']).toEqual(['SCRAPER_DB_PASSWORD']);
    for (const [, svc] of services) {
      for (const value of Object.values(svc.environment ?? {})) {
        expect(String(value)).not.toMatch(/password=|:[^@/]+@/i);
      }
    }
  });

  it('routes and health checks point at a real service and port', () => {
    const runner = fragment.services['scraper-runner']!;
    expect(runner.environment.PORT).toBe(String(manifest.routes[0].internal_port));
    expect(runner.environment.SEALED_AGENT_URL).toBe('http://sealed-agent:7070');
    expect(runner.environment.CRAWLEE_PERSIST_STORAGE).toBe('false');
    // Only Caddy, whose apps-network address is fixed by INTERFACES 6, may call the runner.
    expect(runner.environment.SCRAPER_ALLOWED_CLIENTS).toBe('172.30.0.4');
    expect(runner.read_only).toBe(true);
    expect(fragment.services['scraper-db']!.environment.POSTGRES_PASSWORD_FILE).toBe('/run/sealed/secrets/scraper/SCRAPER_DB_PASSWORD');
  });

});

const composer = findComposer(REPO);
const skip = 'skip' in composer ? composer.skip : false;
describe.skipIf(skip)('the real composer (runtime/composer)', () => {
  const c = composer as Composer;
  const notBrief = 'skip' in composer || composer.brief ? false : `composer ${c.version} predates integration brief items 5 to 11`;
  let out: string;
  let stack: Composed;
  beforeAll(() => {
    out = mkdtempSync(join(tmpdir(), 'scraper-composed-'));
    stack = compose(c, [APP], out, ['scraper']);
  }, 600_000);
  afterAll(() => rmSync(out, { recursive: true, force: true }));

  it('sealed-compose lint blocks the release only on the unbuilt runner image (D-028)', () => {
    const findings = lint(c, APP);
    const unexpected = findings.filter(
      (f) => !(f.severity === 'error' && f.code === 'unbuilt-image') && !(f.severity === 'warning' && f.code === 'sbom-missing'),
    );
    expect(unexpected).toEqual([]);
    const unbuilt = manifest.images.filter((i: { digest: string }) => /^sha256:0{64}$/.test(i.digest)).length;
    expect(findings.filter((f) => f.severity === 'error')).toHaveLength(unbuilt);
  }, 600_000);

  it('gates the scraper route and points it at the runner', () => {
    const site = caddySite(stack.caddyfile, 'scraper.34-1-2-3.sslip.io');
    expect(site).toContain('reverse_proxy scraper-runner:8080');
    if (!notBrief) {
      // Integration brief item 9: forward_auth to sealed-agent instead of Caddy basic_auth.
      expect(site).toContain('forward_auth sealed-agent:7070');
      expect(site).toContain('/v1/gate?route=scraper');
      expect(site).not.toContain('basic_auth');
    }
  });

  it('exports exactly the listed secrets to each service', () => {
    for (const [name, svc] of Object.entries(fragment.services)) {
      expect(envexecSecrets(stack.compose.services[name]!), name).toEqual([...(svc['x-sealed-secrets'] ?? [])].sort());
    }
  });

  it.skipIf(notBrief)('mounts exactly the listed secret files into each service', () => {
    for (const [name, svc] of Object.entries(fragment.services)) {
      const want = (svc['x-sealed-secrets'] ?? []).map((s: string) => `/run/sealed/secrets/scraper/${s}`).sort();
      expect(secretMounts(stack.compose.services[name]!, 'scraper'), name).toEqual(want);
    }
  });

  it.skipIf(notBrief)('sets SEALED_PUBLIC_URL_SCRAPER, which the runner checks request origins against', () => {
    for (const name of Object.keys(fragment.services)) {
      expect(stack.compose.services[name]!.environment.SEALED_PUBLIC_URL_SCRAPER, name).toBe('https://scraper.34-1-2-3.sslip.io');
    }
  });

  const docker = spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' });
  it.runIf(docker.status === 0)('docker compose accepts the composed document', () => {
    const r = spawnSync('docker', ['compose', '-p', 'sealed-scraper-check', '-f', stack.composePath, 'config', '--quiet'], { encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
  });
});

describe('Dockerfiles', () => {
  const variants = {
    slim: read('images/scraper-runner/Dockerfile'),
    playwright: read('images/scraper-runner-playwright/Dockerfile'),
  };
  const froms = (text: string) => [...text.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]!);

  it('pins every base image by digest', () => {
    for (const text of Object.values(variants)) {
      for (const from of froms(text)) if (from !== 'scratch') expect(from).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
    expect(froms(variants.slim)).toContain(
      'node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c',
    );
    expect(froms(variants.playwright)).toContain(
      'mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e',
    );
  });

  it('matches the Playwright image tag to the pinned npm package', () => {
    expect(runnerPkg.optionalDependencies.playwright).toBe('1.62.1');
    expect(variants.playwright).toContain('playwright:v1.62.1-noble');
  });

  it('runs as a non-root user with the fragment entrypoint and memory-only Crawlee storage', () => {
    const entry = JSON.stringify(fragment.services['scraper-runner']!.entrypoint);
    for (const text of Object.values(variants)) {
      const users = [...text.matchAll(/^USER\s+(\S+)/gm)].map((m) => m[1]);
      expect(users.at(-1)).toMatch(/^(node|pwuser)$/);
      expect(text).toContain(`ENTRYPOINT ${entry.replace(/,/g, ', ')}`);
      expect(text).toContain('CRAWLEE_PERSIST_STORAGE=false');
      const instructions = text.split('\n').filter((l) => !l.trimStart().startsWith('#')).join('\n');
      expect(instructions).not.toMatch(/MOZ_DISABLE|--no-sandbox|CRAWLEE_DISABLE_BROWSER_SANDBOX/);
    }
  });

  it('ships only Firefox in the Playwright variant, flattened', () => {
    expect(variants.playwright).toMatch(/rm -rf \/ms-playwright\/chromium-\* \/ms-playwright\/chromium_headless_shell-\*/);
    expect(variants.playwright).toMatch(/^FROM scratch$/m);
    expect(variants.playwright).toMatch(/^COPY --from=rootfs \/ \/$/m);
    expect(variants.slim).toContain('--no-optional');
  });

  it('builds from the runner lockfile with frozen installs', () => {
    for (const text of Object.values(variants)) {
      expect(text).toContain('pnpm install --frozen-lockfile --ignore-workspace');
      expect(text).toContain('pnpm@10.33.2');
    }
  });
});

describe('fixture site', () => {
  const pages = readdirSync(SITE).filter((f) => f.endsWith('.html')).sort();

  it('has 10 HTML pages and a robots.txt', () => {
    expect(pages).toHaveLength(10);
    expect(readFileSync(join(SITE, 'robots.txt'), 'utf8')).toMatch(/^User-agent: \*\nDisallow: \/private\/$/m);
  });

  it('links every page from every page and has the same fields everywhere', () => {
    const job = parseJobSpec(JSON.parse(readFileSync(join(FIXTURES, 'a6-job.json'), 'utf8')));
    expect(job.ok).toBe(false); // FIXTURE_HOST is a placeholder, not a real host name
    const fields = JSON.parse(readFileSync(join(FIXTURES, 'a6-job.json'), 'utf8')).extract as Record<string, string>;
    const paths = new Set(expected.items.map((e) => e.path));
    for (const file of pages) {
      const $ = load(readFileSync(join(SITE, file), 'utf8'));
      const path = file === 'index.html' ? '/' : `/${file}`;
      const links = new Set($('nav a').map((_, a) => new URL($(a).attr('href')!, `https://host${path}`).pathname).get());
      for (const p of paths) expect(links.has(p), `${file} links ${p}`).toBe(true);
      const data = extractFields($, fields, `https://host${path}`);
      const { path: _p, ...want } = expected.items.find((e) => e.path === path)!;
      expect(data, file).toEqual(want);
    }
  });

  it('a6-job.json is valid once the host is filled in', () => {
    const raw = readFileSync(join(FIXTURES, 'a6-job.json'), 'utf8').replace('FIXTURE_HOST', 'fixtures.34-1-2-3.sslip.io');
    expect(parseJobSpec(JSON.parse(raw)).ok).toBe(true);
  });
});
