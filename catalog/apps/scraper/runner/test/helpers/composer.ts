import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Runs the real composer (runtime/composer/cmd/sealed-compose) for the scraper's catalog checks.
// The catalog rules live only there (integration brief item 25), so these tests call
// `go run ./runtime/composer/cmd/sealed-compose lint` and `compose` instead of copying them.
// Switch to catalog/tools/ once that shared tooling exists. The composer is looked up in
// SEALED_COMPOSER_DIR, then in this checkout. Without Go or the composer source the tests skip,
// unless CI or SEALED_REQUIRE_COMPOSER=1 is set; then they fail.

const CLI = './runtime/composer/cmd/sealed-compose';
export const BRIEF_VERSION = [1, 2, 0];
export const REGISTRY = 'ghcr.io/sealedtempo';

export interface Composer {
  dir: string;
  version: string;
  // True when the composer implements integration brief items 5 to 11 (composer 1.2.0).
  brief: boolean;
}

export interface Finding {
  severity: 'error' | 'warning';
  app: string;
  file?: string;
  field?: string;
  code: string;
  message: string;
}

export function findComposer(repo: string): Composer | { skip: string } {
  const dir = resolve(process.env.SEALED_COMPOSER_DIR || repo);
  let reason: string | undefined;
  if (spawnSync('go', ['version'], { encoding: 'utf8' }).status !== 0) reason = 'go is not installed';
  else if (!existsSync(join(dir, CLI, 'main.go'))) reason = `composer source not found under ${dir} (set SEALED_COMPOSER_DIR)`;
  if (reason) {
    if (process.env.SEALED_REQUIRE_COMPOSER === '1' || process.env.CI) throw new Error(`the real composer is required here: ${reason}`);
    return { skip: reason };
  }
  const version = composerVersion(dir);
  const parts = (version.match(/\d+/g) ?? []).map(Number);
  let brief = true;
  for (let i = 0; i < BRIEF_VERSION.length; i++) {
    const have = parts[i] ?? 0;
    if (have !== BRIEF_VERSION[i]) {
      brief = have > BRIEF_VERSION[i]!;
      break;
    }
  }
  return { dir, version, brief };
}

function composerVersion(dir: string): string {
  const src = join(dir, 'runtime/composer');
  for (const file of readdirSync(src).sort()) {
    if (!file.endsWith('.go') || file.endsWith('_test.go')) continue;
    const m = /^const Version = "([^"]+)"/m.exec(readFileSync(join(src, file), 'utf8'));
    if (m) return m[1]!;
  }
  throw new Error('cannot find the composer version');
}

function run(composer: Composer, args: string[]) {
  const res = spawnSync('go', ['run', CLI, ...args], { cwd: composer.dir, encoding: 'utf8', timeout: 600_000 });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

export function lint(composer: Composer, appDir: string): Finding[] {
  const res = run(composer, ['lint', '--json', '--app-dir', appDir]);
  try {
    return JSON.parse(res.stdout) as Finding[];
  } catch {
    throw new Error(`sealed-compose lint failed: ${res.stderr}`);
  }
}

export function sampleConfig(appIds: string[], version: string, brief = true): Record<string, unknown> {
  const word = (byte: string, n: number) => `0x${byte.repeat(n)}`;
  const config: Record<string, unknown> = {
    schema: 'sealed-config/v1',
    chainId: 4217,
    customer: `${word('0', 38)}c1`,
    salt: word('5a', 32),
    imageId: word('1d', 32),
    composerVersion: version,
    apps: [...appIds].sort().map((id) => ({ id, releaseId: word('00', 32) })),
    hostnames: { scheme: 'sslip', ip: '34.1.2.3' },
    egressAdditions: {},
    allowedVpcRanges: [],
    endpoints: {
      keyBroker: 'https://sealed-key-broker-xyz.a.run.app',
      platformApi: 'https://api.sealed.example',
      tempoRpc: 'https://rpc.tempo.xyz',
      // The relay is served on its deployment's attest host (D-045).
      relay: 'https://attest.relay.sealed.example',
      relayAttest: 'https://attest.relay.sealed.example/attest',
    },
    contracts: {
      platformRegistry: `${word('0', 38)}e1`,
      appRegistry: `${word('0', 38)}e2`,
      deploymentRegistry: `${word('0', 38)}e3`,
      feeSplitter: `${word('0', 38)}e4`,
    },
    feeToken: '0x20c000000000000000000000b9537d11c60e8b50',
    settlement: { mode: 'access-key', intervalMinutes: 60, gracePeriodMinutes: 1440, spendLimitPerDay: '2000000' },
    relayOwner: `${word('0', 38)}b1`,
  };
  if (brief) config.debug = false; // integration brief item 13, composer 1.2.0
  return config;
}

export interface Composed {
  caddyfile: string;
  compose: { services: Record<string, Record<string, any>> };
  composePath: string;
  stack: { apps: Array<Record<string, any>> };
}

export function compose(composer: Composer, appDirs: string[], outDir: string, appIds: string[]): Composed {
  mkdirSync(outDir, { recursive: true });
  const configPath = join(outDir, 'input-config.json');
  writeFileSync(configPath, JSON.stringify(sampleConfig(appIds, composer.version, composer.brief)));
  const args = ['compose', '--config', configPath, '--fill-release-ids', '--allow-missing-sbom', '--registry', REGISTRY, '--out', outDir];
  for (const d of appDirs) args.push('--app-dir', d);
  const res = run(composer, args);
  if (res.status !== 0) throw new Error(`sealed-compose compose failed: ${res.stderr}`);
  const read = (name: string) => readFileSync(join(outDir, name), 'utf8');
  return {
    caddyfile: read('Caddyfile'),
    compose: JSON.parse(read('docker-compose.json')),
    composePath: join(outDir, 'docker-compose.json'),
    stack: JSON.parse(read('stack.json')),
  };
}

// The block of one site ("<host> {" to the "}" at column 0) in a rendered Caddyfile.
export function caddySite(caddyfile: string, host: string): string | undefined {
  const lines = caddyfile.split('\n');
  const start = lines.indexOf(`${host} {`);
  if (start < 0) return undefined;
  const end = lines.findIndex((l, i) => i > start && l === '}');
  return lines.slice(start, end + 1).join('\n');
}

// Secret names a composed service's envexec entrypoint exports (--secret / --optional-secret).
export function envexecSecrets(service: Record<string, any>): string[] {
  const entry = service.entrypoint as string[];
  const sep = entry.indexOf('--');
  const names: string[] = [];
  for (let i = 0; i < sep; i++) if (entry[i] === '--secret' || entry[i] === '--optional-secret') names.push(entry[i + 1]!);
  return names.sort();
}

// Targets of a composed service's mounts under /run/sealed/secrets/<appId>.
export function secretMounts(service: Record<string, any>, appId: string): string[] {
  const root = `/run/sealed/secrets/${appId}`;
  return ((service.volumes ?? []) as Array<string | { target?: string }>)
    .map((v) => (typeof v === 'string' ? v.split(':')[1] : v.target))
    .filter((t): t is string => t === root || Boolean(t?.startsWith(`${root}/`)))
    .sort();
}
