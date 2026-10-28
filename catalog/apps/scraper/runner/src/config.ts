import { readFileSync } from 'node:fs';
import type { LogLevel } from './log.js';

export const ROBOTS_PRODUCT_TOKEN = 'SealedScraper';
export const DEFAULT_USER_AGENT = `${ROBOTS_PRODUCT_TOKEN}/1.0 (+https://github.com/sealed-dev/sealed/tree/main/catalog/apps/scraper)`;

export interface Config {
  host: string;
  port: number;
  databaseUrl: string;
  dbPassword: string | undefined;
  // sealed-egress. Undefined only when SCRAPER_ALLOW_NO_PROXY=1 (local development).
  proxyUrl: string | undefined;
  agentUrl: string | undefined;
  meterFlushMs: number;
  meterMaxBatch: number;
  maxRuns: number;
  userAgent: string;
  robotsUserAgent: string;
  memoryMbytes: number;
  crawlers: string[] | undefined;
  logLevel: LogLevel;
}

export class ConfigError extends Error {}

type Env = Record<string, string | undefined>;

function int(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new ConfigError(`${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

function httpUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${name} is not a valid URL`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigError(`${name} must be an http or https URL`);
  }
  return value;
}

export function resolveProxyUrl(env: Env): string | undefined {
  const candidates = ['SCRAPER_PROXY_URL', 'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy'];
  for (const name of candidates) {
    const value = env[name];
    if (value) return httpUrl(name, value);
  }
  return undefined;
}

function readPassword(env: Env, readFile: (path: string) => string): string | undefined {
  if (env.SCRAPER_DB_PASSWORD) return env.SCRAPER_DB_PASSWORD;
  const file = env.SCRAPER_DB_PASSWORD_FILE;
  if (!file) return undefined;
  try {
    return readFile(file).replace(/\r?\n$/, '');
  } catch {
    throw new ConfigError('SCRAPER_DB_PASSWORD_FILE is set but cannot be read');
  }
}

export function loadConfig(env: Env = process.env, readFile = (p: string) => readFileSync(p, 'utf8')): Config {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) throw new ConfigError('DATABASE_URL is required');

  const proxyUrl = resolveProxyUrl(env);
  if (!proxyUrl && env.SCRAPER_ALLOW_NO_PROXY !== '1') {
    throw new ConfigError('HTTP_PROXY (sealed-egress) is required; set SCRAPER_ALLOW_NO_PROXY=1 only for local development');
  }

  const metering = env.SCRAPER_METERING ?? 'on';
  if (metering !== 'on' && metering !== 'off') throw new ConfigError('SCRAPER_METERING must be on or off');
  const agentUrl = metering === 'on' ? httpUrl('SEALED_AGENT_URL', env.SEALED_AGENT_URL ?? 'http://sealed-agent:7070') : undefined;

  const logLevel = (env.LOG_LEVEL ?? 'info') as LogLevel;
  if (!['debug', 'info', 'warn', 'error'].includes(logLevel)) throw new ConfigError('LOG_LEVEL must be debug, info, warn or error');

  const crawlers = env.SCRAPER_CRAWLERS
    ? env.SCRAPER_CRAWLERS.split(',').map((s) => s.trim()).filter(Boolean)
    : undefined;

  return {
    host: env.HOST ?? '0.0.0.0',
    port: int(env, 'PORT', 8080, 1, 65535),
    databaseUrl,
    dbPassword: readPassword(env, readFile),
    proxyUrl,
    agentUrl,
    meterFlushMs: int(env, 'SCRAPER_METER_FLUSH_MS', 5000, 100, 600_000),
    meterMaxBatch: int(env, 'SCRAPER_METER_MAX_BATCH', 50, 1, 100_000),
    maxRuns: int(env, 'SCRAPER_MAX_RUNS', 2, 1, 8),
    userAgent: env.SCRAPER_USER_AGENT || DEFAULT_USER_AGENT,
    robotsUserAgent: ROBOTS_PRODUCT_TOKEN,
    memoryMbytes: int(env, 'CRAWLEE_MEMORY_MBYTES', 2048, 256, 65536),
    crawlers,
    logLevel,
  };
}
