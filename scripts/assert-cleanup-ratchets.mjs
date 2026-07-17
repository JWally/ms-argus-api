import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const limits = new Map([
  ["src/helpers/merchant-projection.ts", 874],
  ["src/handlers/ingestion/base-handler.ts", 480],
  ["src/handlers/ingestion/device-history-workflow.ts", 112],
  ["src/handlers/ingestion/integrity-record-builder.ts", 121],
  ["src/handlers/ingestion/integrity-analysis.ts", 242],
  ["src/handlers/ingestion/ip-velocity.ts", 103],
  ["src/handlers/ingestion/persist-integrity-record.ts", 80],
  ["src/handlers/ingestion/sigint-hydration.ts", 111],
  ["src/scoring/automation.ts", 269],
  ["src/scoring/device-tampering.ts", 321],
  ["src/scoring/identity.ts", 194],
  ["src/projections/activity.ts", 100],
]);

function lineCount(path) {
  const url = new URL(`../${path}`, import.meta.url);
  const source = readFileSync(fileURLToPath(url), "utf8");
  const lines = source.split("\n").length;
  return source.endsWith("\n") ? lines - 1 : lines;
}

const violations = [];
for (const [path, maximum] of limits) {
  const actual = lineCount(path);
  if (actual > maximum) {
    violations.push(`${path}: ${actual} lines exceeds ratchet ${maximum}`);
  } else {
    process.stdout.write(`${path}: ${actual}/${maximum} lines\n`);
  }
}

if (violations.length > 0) {
  process.stderr.write(
    `Cleanup ratchet failed:\n${violations.map((v) => `- ${v}`).join("\n")}\n`,
  );
  process.exitCode = 1;
}
