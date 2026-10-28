import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/setup/postgres.global.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    env: {
      CRAWLEE_PERSIST_STORAGE: 'false',
      CRAWLEE_LOG_LEVEL: 'OFF',
    },
  },
});
