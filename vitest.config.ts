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
      exclude: ["**/*.test.ts", "**/*.d.ts", "node_modules", "dist", "cdk.out"],
      thresholds: {
        // Current: statements 57%, branches 94%, functions 97%, lines 57%
        // Set ~10% below current to catch regressions while allowing flexibility
        statements: 50,
        branches: 85,
        functions: 90,
        lines: 50,
      },
    },
  },
});
