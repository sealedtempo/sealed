// Whether the Postgres-backed tests may be skipped. On CI (CI set) or with SCRAPER_REQUIRE_PG=1 a
// missing PostgreSQL fails the run instead of silently skipping persistence and end-to-end
// coverage. SCRAPER_SKIP_PG=1 skips on purpose, except when SCRAPER_REQUIRE_PG=1 is also set.

type Env = Record<string, string | undefined>;

const truthy = (v: string | undefined) => v !== undefined && v !== '' && v !== '0' && v.toLowerCase() !== 'false';

export function pgPolicy(env: Env): { skip: boolean; required: boolean } {
  const skip = env.SCRAPER_SKIP_PG === '1';
  const required = env.SCRAPER_REQUIRE_PG === '1' || (truthy(env.CI) && !skip);
  return { skip: skip && !required, required };
}
