import type pg from 'pg';
import { MIGRATIONS, type Migration } from './migrations.js';

// Arbitrary constant: serializes concurrent migrators (two runner replicas starting at once).
const LOCK_KEY = 727_273_001;

export async function migrate(pool: pg.Pool, migrations: Migration[] = MIGRATIONS): Promise<number[]> {
  const client = await pool.connect();
  const applied: number[] = [];
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version integer PRIMARY KEY,
        name text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);
    const { rows } = await client.query<{ version: number }>('SELECT version FROM schema_migrations');
    const done = new Set(rows.map((r) => r.version));
    for (const m of [...migrations].sort((a, b) => a.version - b.version)) {
      if (done.has(m.version)) continue;
      await client.query('BEGIN');
      try {
        await client.query(m.sql);
        await client.query('INSERT INTO schema_migrations (version, name) VALUES ($1, $2)', [m.version, m.name]);
        await client.query('COMMIT');
        applied.push(m.version);
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => undefined);
    client.release();
  }
  return applied;
}
