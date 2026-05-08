import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["src/**/*.test.ts", "lib/**/*.test.ts"],
    exclude: ["node_modules", "dist", "cdk.out", "cmd"],
    server: {
      deps: {
        inline: ["@silverbucket/ajv-formats-draft2019"],
      },
    },
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "json-summary", "lcov", "html"],
      reportsDirectory: "./coverage",
      all: true,
      clean: true,
      include: ["src/**/*.ts"],
      exclude: [
        "**/*.test.ts",
        "**/*.d.ts",
        "node_modules",
        "dist",
        "cdk.out",
        "src/types/**",
        "**/index.ts",
        // Lambda entry-point shells (middy config + env wiring only — actual
        // logic lives in handlers/*/base-handler.ts). Integration tests for
        // these paths were removed with the matching pipeline.
        "src/handlers/ingestion.ts",
        "src/handlers/session-get.ts",
        "src/handlers/ingestion/base-handler.ts",
        "src/handlers/session-get/base-handler.ts",
        "src/handlers/session-get/session-ops.ts",
        "src/handlers/integrity-archiver.ts",
        // ECDH / ingestion middleware paths exercised only via integration
        // tests which were dropped with the /v1/collect pipeline.
        "src/handlers/ingestion/middleware.ts",
        "src/config/env.ts",
        // AWS infra helpers (SSM, Secrets, ECDH key retrieval) — exercised
        // end-to-end but not unit-testable without a mock AWS env.
        "src/helpers/get-ecdh-keys.ts",
        "src/helpers/bucket-keys.ts",
        "src/helpers/is-warmup.ts",
        "src/helpers/ecdh-decrypt.ts",
        "src/helpers/integrity-api-key.ts",
        "src/helpers/cors-middleware.ts",
        "src/helpers/env-validation.ts",
        "src/helpers/error-middleware.ts",
        "src/helpers/middy-helpers.ts",
        "src/services/profile/anomaly/tls-maps.ts",
        "src/services/profile/anomaly/network-probe-detector.ts",
        // ip-class-builder Lambda fetches the IPtoASN dataset and uploads to
        // S3 — same exclusion shape as other AWS-dependent handlers.
        "src/handlers/ip-class-builder.ts",
        // ip-class-discoverer Lambda walks S3 archive + RDAP + S3 upload —
        // entirely network I/O; same exclusion shape.
        "src/handlers/ip-class-discoverer.ts",
        // S3-backed dataset loaders — sync classifier + cache hooks are
        // exercised via integration tests; load paths need S3 mock.
        "src/services/network/asn-classifier.ts",
        "src/services/network/auto-overlay.ts",
        // RDAP client — pure HTTP client; logic is testable but mocking
        // 5 RIR endpoints adds little value over the empirical POC results.
        "src/services/network/rdap-client.ts",
        // Pure data file — no logic to unit-test.
        "src/services/network/asn-overrides.ts",
      ],
      thresholds: {
        statements: 88,
        branches: 85,
        functions: 92,
        lines: 88,
      },
    },
  },
});
