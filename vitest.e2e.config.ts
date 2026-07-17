import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["tests/e2e/**/*.e2e.test.ts"],
    fileParallelism: false,
    env: {
      INTEGRITY_RESULTS_TABLE: "e2e-integrity-results",
      MERCHANTS_TABLE_NAME: "e2e-merchants",
      PLATFORM_PUBKEY_SSM_PATH: "/e2e/platform-signing-key",
      SIGINT_AES_KEY:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      PROBE_TOKENS_TABLE_NAME: "e2e-probe-tokens",
      POWERTOOLS_SERVICE_NAME: "argus-e2e",
      POWERTOOLS_METRICS_NAMESPACE: "argus-e2e",
    },
  },
});
