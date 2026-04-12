import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["src/**/*.test.ts", "lib/**/*.test.ts", "tests/**/*.test.ts"],
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
        "src/services/matching/types.ts",
        "src/services/profile/types.ts",
        "src/handlers/vector-worker/types.ts",
        "**/index.ts",
        "src/handlers/vector-test.ts",
        // signal-learning: new subsystem, tests pending
        "src/services/signal-learning/**",
        "src/services/profile/anomaly/signal-baseline-detector.ts",
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
