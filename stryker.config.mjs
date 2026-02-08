export default {
  testRunner: "vitest",
  reporters: ["clear-text", "html"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
  mutate: ["src/**/*.ts", "!src/**/*.test.ts", "!src/types/**"],
  thresholds: {
    high: 80,
    low: 60,
    break: 50,
  },
  concurrency: 4,
  timeoutMS: 30000,
  vitest: {
    configFile: "vitest.config.ts",
  },
};
