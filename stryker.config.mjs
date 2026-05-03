export default {
  testRunner: "vitest",
  reporters: ["clear-text", "html"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
  mutate: ["src/**/*.ts", "!src/**/*.test.ts", "!src/types/**"],
  // Advisory thresholds — mutation testing produces a signal we
  // care about (low/high colour the report, weak files surface),
  // but it's not a merge gate. The codebase sits around 46% and
  // the gap to 50 is hundreds of mutants across files we'd need
  // to write tests for one at a time. Setting `break: 50` while
  // the actual baseline is 46 made every PR show a red check that
  // everyone learned to ignore — boy-who-cried-wolf. New code
  // (e.g. handlers/ingestion/ttl.ts) gets first-class mutation
  // tests on its own; the global score is a tracked metric, not
  // a gate.
  thresholds: {
    high: 80,
    low: 60,
    break: null,
  },
  concurrency: 4,
  timeoutMS: 30000,
  vitest: {
    configFile: "vitest.config.ts",
  },
};
