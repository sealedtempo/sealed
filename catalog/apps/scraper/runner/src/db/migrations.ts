// Append-only. Never edit a released migration; add a new one.

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'runs_items_events',
    sql: `
      CREATE TABLE runs (
        id uuid PRIMARY KEY,
        status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
        crawler text NOT NULL CHECK (crawler IN ('cheerio', 'playwright')),
        -- json, not jsonb: jsonb reorders keys, and the order of extract fields is the export column order.
        spec json NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz,
        finished_at timestamptz,
        pages_ok integer NOT NULL DEFAULT 0,
        pages_failed integer NOT NULL DEFAULT 0,
        pages_skipped integer NOT NULL DEFAULT 0,
        error text
      );
      CREATE INDEX runs_created_at_idx ON runs (created_at DESC, id DESC);
      CREATE INDEX runs_status_idx ON runs (status) WHERE status IN ('queued', 'running');

      CREATE TABLE items (
        id bigserial PRIMARY KEY,
        run_id uuid NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
        url text NOT NULL,
        status_code integer,
        data jsonb NOT NULL,
        fetched_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX items_run_id_id_idx ON items (run_id, id);

      CREATE TABLE run_events (
        id bigserial PRIMARY KEY,
        run_id uuid NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('failed', 'skipped')),
        url text NOT NULL,
        detail text NOT NULL,
        at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX run_events_run_id_id_idx ON run_events (run_id, id);
    `,
  },
  {
    version: 2,
    name: 'run_events_robots_and_limit',
    sql: `
      ALTER TABLE run_events DROP CONSTRAINT run_events_kind_check;
      ALTER TABLE run_events ADD CONSTRAINT run_events_kind_check
        CHECK (kind IN ('failed', 'skipped', 'robots', 'limit'));
    `,
  },
];
