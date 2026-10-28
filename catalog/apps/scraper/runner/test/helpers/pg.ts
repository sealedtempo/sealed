import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { inject } from 'vitest';

export const pgUrl = inject('pgUrl');
export const hasPostgres = pgUrl !== '';

export interface TestDatabase {
  url: string;
  pool: pg.Pool;
  drop(): Promise<void>;
}

// A fresh database in the shared throwaway cluster.
export async function createTestDatabase(): Promise<TestDatabase> {
  const name = `scraper_test_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: pgUrl });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const url = new URL(pgUrl);
  url.pathname = `/${name}`;
  const pool = new pg.Pool({ connectionString: url.toString(), max: 5 });
  return {
    url: url.toString(),
    pool,
    drop: async () => {
      await pool.end();
      const c = new pg.Client({ connectionString: pgUrl });
      await c.connect();
      await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await c.end();
    },
  };
}
