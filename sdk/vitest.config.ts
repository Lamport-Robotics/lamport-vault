import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const lmsSrc = fileURLToPath(new URL("./packages/lms/src/index.ts", import.meta.url));

export default defineConfig({
  resolve: {
    // Tests run against sources, so no build step is needed before `npm test`.
    alias: { "@lamport-robotics/lms": lmsSrc },
  },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
