import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const packageJson = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

const actual = [...(packageJson.knip?.entry ?? [])].sort();
const expected = ["bin/*.ts", "lib/**/*.ts", "src/handlers/*.ts"].sort();

assert.deepEqual(
  actual,
  expected,
  [
    "Knip entry points must stay limited to deployable roots.",
    "Do not hide dead code by adding broad helper, service, or type globs.",
    "Add a concrete runtime entry only when deployment wiring proves it is one.",
  ].join(" "),
);

process.stdout.write(`Knip entry-point policy: ${actual.join(", ")}\n`);
