import { migrate } from '../src/db/migrate.js';
import { PgRunStore } from '../src/db/store.js';
import { MemoryRunStore } from './helpers/memory-store.js';
import { createTestDatabase, hasPostgres } from './helpers/pg.js';
import { describeRunStoreContract } from './helpers/store-contract.js';

describeRunStoreContract('MemoryRunStore', true, async () => ({ store: new MemoryRunStore(), close: async () => {} }));

describeRunStoreContract('PgRunStore', hasPostgres, async () => {
  const db = await createTestDatabase();
  await migrate(db.pool);
  return { store: new PgRunStore(db.pool), close: () => db.drop() };
});
