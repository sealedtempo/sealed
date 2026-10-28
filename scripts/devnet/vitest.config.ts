import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Unit tests run against the sources, so no build is needed first.
    alias: [
      { find: /^@sealed\/core\/testing$/, replacement: fileURLToPath(new URL("../../packages/core/src/testing/index.ts", import.meta.url)) },
      { find: /^@sealed\/core$/, replacement: fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)) },
      { find: /^@sealed\/agent\/dist\/src\/(.*)\.js$/, replacement: fileURLToPath(new URL("../../runtime/agent/src/$1.ts", import.meta.url)) },
    ],
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
  },
});
