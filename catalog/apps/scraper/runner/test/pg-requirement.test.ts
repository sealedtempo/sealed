import { describe, expect, it } from 'vitest';
import { pgPolicy } from './setup/pg-requirement.js';

describe('pgPolicy', () => {
  it('may skip locally when Postgres is missing', () => {
    expect(pgPolicy({})).toEqual({ skip: false, required: false });
    expect(pgPolicy({ SCRAPER_SKIP_PG: '1' })).toEqual({ skip: true, required: false });
  });

  it('requires Postgres on CI unless skipped on purpose', () => {
    expect(pgPolicy({ CI: 'true' })).toEqual({ skip: false, required: true });
    expect(pgPolicy({ CI: '1' }).required).toBe(true);
    expect(pgPolicy({ CI: 'false' }).required).toBe(false);
    expect(pgPolicy({ CI: 'true', SCRAPER_SKIP_PG: '1' })).toEqual({ skip: true, required: false });
  });

  it('SCRAPER_REQUIRE_PG=1 always wins', () => {
    expect(pgPolicy({ SCRAPER_REQUIRE_PG: '1', SCRAPER_SKIP_PG: '1' })).toEqual({ skip: false, required: true });
  });
});
