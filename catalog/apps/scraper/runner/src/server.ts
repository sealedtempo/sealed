import { dropSecrets } from './env-guard.js';
import { log as crawleeLog } from '@crawlee/core';
import { serve } from '@hono/node-server';
import { loadConfig } from './config.js';
import { createCrawl, detectCrawlers } from './crawl/index.js';
import { migrate } from './db/migrate.js';
import { createPool, waitForDatabase } from './db/pool.js';
import { PgRunStore } from './db/store.js';
import { createApp } from './http/app.js';
import { createLogger, errorMessage } from './log.js';
import { noopMeter, UsageMeter } from './meter.js';
import { RunManager } from './runs/manager.js';

async function main(): Promise<void> {
  const config = loadConfig();
  dropSecrets(process.env);
  const log = createLogger(config.logLevel);
  // Crawlee logs every URL it touches at INFO; keep only its warnings and errors.
  crawleeLog.setLevel(crawleeLog.LEVELS.WARNING);

  const pool = createPool(config.databaseUrl, config.dbPassword, log);
  await waitForDatabase(pool, log);
  const applied = await migrate(pool);
  if (applied.length > 0) log.info('database migrated', { versions: applied });
  const store = new PgRunStore(pool);

  const meter = config.agentUrl
    ? new UsageMeter({ agentUrl: config.agentUrl, flushMs: config.meterFlushMs, maxBatch: config.meterMaxBatch, log })
    : noopMeter;
  meter.start();

  const crawlers = await detectCrawlers(config.crawlers);
  const manager = new RunManager({
    store,
    meter,
    log,
    maxRuns: config.maxRuns,
    crawl: createCrawl({
      proxyUrl: config.proxyUrl,
      userAgent: config.userAgent,
      robotsUserAgent: config.robotsUserAgent,
      memoryMbytes: config.memoryMbytes,
    }),
  });
  await manager.start();

  const app = createApp({ store, runs: manager, crawlers, log, clients: config.allowedClients });
  const server = serve({ fetch: app.fetch, port: config.port, hostname: config.host });
  log.info('scraper-runner listening', {
    port: config.port,
    clients: config.allowedClients.entries,
    crawlers,
    proxy: Boolean(config.proxyUrl),
    metering: Boolean(config.agentUrl),
  });

  let stopping = false;
  const stop = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info('shutting down', { signal });
    server.close();
    await manager.shutdown();
    await meter.stop();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));
}

main().catch((err: unknown) => {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'startup failed', error: errorMessage(err) }) + '\n');
  process.exit(1);
});
