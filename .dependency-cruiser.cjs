/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: "no-circular",
      severity: "error",
      comment: "Circular dependencies make code hard to follow and refactor.",
      from: {},
      to: { circular: true },
    },
    {
      name: "types-no-imports",
      severity: "error",
      comment: "Types should be pure definitions - no imports from application code.",
      from: { path: "^src/types/" },
      to: { path: "^src/(handlers|services|helpers|config)/" },
    },
    {
      name: "config-no-logic-imports",
      severity: "error",
      comment: "Config should not depend on application logic.",
      from: { path: "^src/config/" },
      to: { path: "^src/(handlers|services|helpers)/" },
    },
    {
      name: "helpers-no-handler-or-service-imports",
      severity: "error",
      comment: "Helpers are low-level utilities - they should not depend on handlers or services.",
      from: { path: "^src/helpers/", pathNot: "\\.test\\.ts$" },
      to: { path: "^src/(handlers|services)/" },
    },
    {
      name: "no-orphans",
      severity: "warn",
      comment: "Modules that are not imported by anything may be dead code.",
      from: {
        orphan: true,
        pathNot: [
          "(^|/)\\.[^/]+\\.(cjs|mjs|js|ts)$", // dot files
          "\\.test\\.ts$", // test files
          "^src/handlers/", // Lambda entry points
          "^bin/", // CLI entry points
          "^lib/", // CDK constructs
          "^scripts/", // utility scripts
          "^tests/", // test utilities
        ],
      },
      to: {},
    },
    {
      name: "no-dev-deps-in-src",
      severity: "error",
      comment: "Production code should not import devDependencies.",
      from: { path: "^src/", pathNot: "\\.test\\.ts$" },
      to: { dependencyTypes: ["npm-dev"], pathNot: "^node_modules/@types/" },
    },
  ],
  options: {
    doNotFollow: {
      path: "node_modules",
    },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: "./tsconfig.json" },
    exclude: {
      path: ["dist", "cdk.out", "coverage", "cmd"],
    },
    reporterOptions: {
      text: { highlightFocused: true },
    },
  },
};
