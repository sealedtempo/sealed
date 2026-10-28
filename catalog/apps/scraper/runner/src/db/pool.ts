import pg from 'pg';
import { errorMessage, type Logger } from '../log.js';

// DATABASE_URL is public (it is in the compose fragment) and carries no password; the password
// comes from the secret store. pg lets an empty password in the URL override a separate
// `password` option, so the secret is placed into the URL in memory instead.
export function poolConfig(databaseUrl: string, password: string | undefined, max = 10): pg.PoolConfig {
  const url = new URL(databaseUrl);
  if (password) url.password = password;
  return { connectionString: url.toString(), max, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000 };
}

export function createPool(databaseUrl: string, password: string | undefined, log: Logger): pg.Pool {
  const pool = new pg.Pool(poolConfig(databaseUrl, password));
  pool.on('error', (err) => log.error('idle database connection failed', { error: errorMessage(err) }));
  return pool;
}

export async function waitForDatabase(pool: pg.Pool, log: Logger, attempts = 30, delayMs = 2_000): Promise<void> {
  for (let i = 1; ; i++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      if (i >= attempts) throw err;
      log.warn('database not ready, retrying', { attempt: i, error: errorMessage(err) });
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}
