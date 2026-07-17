import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const limits = new Map([
  ["src/helpers/merchant-projection.ts", 1791],
  ["src/handlers/ingestion/base-handler.ts", 1233],
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
