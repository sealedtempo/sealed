import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Tests run against the core sources, so no build is needed first.
    alias: [
      { find: /^@sealed\/core\/testing$/, replacement: fileURLToPath(new URL("../../packages/core/src/testing/index.ts", import.meta.url)) },
      { find: /^@sealed\/core$/, replacement: fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)) },
    ],
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
