/**
 * Analyze decompressed payload data
 *
 * Run: npx ts-node scripts/analyze-payloads-v2.ts
 */
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { gunzipSync } from "zlib";

const dynamodb = new DynamoDBClient({ region: "us-east-1" });
const tableName = "ms-argus-api-dev-jw-session-payload";

interface FieldStats {
  count: number;
  nullCount: number;
  uniqueValues: Set<string>;
  sampleValues: string[];
  numericMin?: number;
  numericMax?: number;
}

const fieldStats: Record<string, FieldStats> = {};

function analyzeValue(path: string, value: unknown) {
  if (!fieldStats[path]) {
    fieldStats[path] = {
      count: 0,
      nullCount: 0,
      uniqueValues: new Set(),
      sampleValues: [],
    };
  }

  const stats = fieldStats[path];
  stats.count++;

  if (value === null || value === undefined) {
    stats.nullCount++;
    return;
  }

  const strVal =
    typeof value === "object" ? JSON.stringify(value) : String(value);

  if (stats.uniqueValues.size < 100) {
    stats.uniqueValues.add(strVal);
  }

  if (stats.sampleValues.length < 5 && !stats.sampleValues.includes(strVal)) {
    stats.sampleValues.push(strVal.slice(0, 100));
  }

  if (typeof value === "number") {
    stats.numericMin =
      stats.numericMin === undefined
        ? value
        : Math.min(stats.numericMin, value);
    stats.numericMax =
      stats.numericMax === undefined
        ? value
        : Math.max(stats.numericMax, value);
  }
}

function walkObject(obj: unknown, path = "", depth = 0) {
  if (depth > 10) return; // Prevent infinite recursion

  if (obj === null || obj === undefined) {
    analyzeValue(path, obj);
    return;
  }

  if (Array.isArray(obj)) {
    analyzeValue(path, `[array:${obj.length}]`);
    if (obj.length > 0 && typeof obj[0] !== "object") {
      // For arrays of primitives, just note the type
      analyzeValue(`${path}[]`, obj[0]);
    } else {
      // Sample first element of object arrays
      if (obj.length > 0) {
        walkObject(obj[0], `${path}[]`, depth + 1);
      }
    }
    return;
  }

  if (typeof obj === "object") {
    for (const [key, val] of Object.entries(obj)) {
      const newPath = path ? `${path}.${key}` : key;
      if (typeof val === "object" && val !== null && !Array.isArray(val)) {
        walkObject(val, newPath, depth + 1);
      } else {
        walkObject(val, newPath, depth + 1);
      }
    }
    return;
  }

  analyzeValue(path, obj);
}

function decompressPayload(
  item: Record<string, any>,
): Record<string, any> | null {
  if (item.payload_gzip_b64) {
    try {
      const compressed = Buffer.from(item.payload_gzip_b64, "base64");
      const decompressed = gunzipSync(compressed);
      return JSON.parse(decompressed.toString());
    } catch (e) {
      console.error("Failed to decompress payload:", e);
      return null;
    }
  }
  return item.payload || null;
}

async function main() {
  console.log("Scanning payload table...\n");

  let totalItems = 0;
  let lastKey: Record<string, any> | undefined;

  while (totalItems < 50) {
    const result = await dynamodb.send(
      new ScanCommand({
        TableName: tableName,
        Limit: 25,
        ExclusiveStartKey: lastKey,
      }),
    );

    if (result.Items) {
      for (const item of result.Items) {
        const unmarshalled = unmarshall(item);
        const payload = decompressPayload(unmarshalled);

        if (!payload) continue;
        totalItems++;

        // Analyze the device section
        if (payload.device) {
          walkObject(payload.device, "device");
        }

        // Analyze sigint section
        if (payload.sigint) {
          walkObject(payload.sigint, "sigint");
        }

        // Analyze hashes section
        if (payload.hashes) {
          walkObject(payload.hashes, "hashes");
        }

        // Analyze identifiers
        if (payload.identifiers) {
          walkObject(payload.identifiers, "identifiers");
        }
      }
    }

    lastKey = result.LastEvaluatedKey;
    if (!lastKey) break;
  }

  console.log(`Analyzed ${totalItems} payloads\n`);

  // Print analysis
  const sortedFields = Object.entries(fieldStats).sort((a, b) =>
    a[0].localeCompare(b[0]),
  );

  // Focus on embedding-relevant fields
  console.log("=".repeat(80));
  console.log("FIELDS USED IN CURRENT EMBEDDING (embedding.ts)");
  console.log("=".repeat(80));

  const embeddingFields = [
    // Structural hashes
    "hashes.html_element",
    "hashes.maths",
    "hashes.window_features",
    "hashes.css",
    "hashes.svg",
    "hashes.intl",
    // Rendering
    "hashes.canvas2d",
    "hashes.canvasWebgl",
    "hashes.offlineAudioContext",
    "hashes.client_rects",
    "device.canvasWebgl.gpu",
    // Hardware
    "device.navigator.hardwareConcurrency",
    "device.navigator.deviceMemory",
    "device.canvasWebgl.extensions",
    "device.screen",
    // Network
    "sigint.tlsFingerprint.ja3",
    "sigint.tlsFingerprint.ja4",
    "sigint.tcpProbe",
    "sigint.tlsFingerprint.ip",
    // Behavioral
    "device.timezone",
    "device.headless",
    // Identity
    "hashes.stable",
    "hashes.fuzzy",
  ];

  for (const prefix of embeddingFields) {
    const matching = sortedFields.filter(([path]) => path.startsWith(prefix));
    if (matching.length > 0) {
      for (const [path, stats] of matching.slice(0, 3)) {
        const coverage = (
          ((stats.count - stats.nullCount) / stats.count) *
          100
        ).toFixed(0);
        console.log(`\n${path}`);
        console.log(
          `  Coverage: ${coverage}% (${stats.count - stats.nullCount}/${stats.count})`,
        );
        console.log(
          `  Unique: ${stats.uniqueValues.size}${stats.uniqueValues.size >= 100 ? "+" : ""}`,
        );
        if (stats.numericMin !== undefined) {
          console.log(`  Range: ${stats.numericMin} - ${stats.numericMax}`);
        }
        if (stats.sampleValues.length > 0) {
          console.log(
            `  Samples: ${stats.sampleValues.slice(0, 2).join(" | ").slice(0, 80)}`,
          );
        }
      }
    }
  }

  // IP Address analysis
  console.log("\n" + "=".repeat(80));
  console.log("IP ADDRESS FIELDS");
  console.log("=".repeat(80));

  const ipFields = sortedFields.filter(
    ([path]) => path.toLowerCase().includes("ip") && !path.includes("script"),
  );

  for (const [path, stats] of ipFields) {
    const coverage = (
      ((stats.count - stats.nullCount) / stats.count) *
      100
    ).toFixed(0);
    console.log(`\n${path}`);
    console.log(`  Coverage: ${coverage}%`);
    console.log(`  Unique: ${stats.uniqueValues.size}`);
    console.log(`  Samples: ${stats.sampleValues.slice(0, 3).join(", ")}`);
  }

  // Fields NOT in embedding but potentially useful
  console.log("\n" + "=".repeat(80));
  console.log("POTENTIALLY USEFUL FIELDS NOT IN EMBEDDING");
  console.log("=".repeat(80));

  const embeddingPaths = embeddingFields.flatMap((p) =>
    sortedFields.filter(([path]) => path.startsWith(p)).map(([path]) => path),
  );
  const unusedHighCoverage = sortedFields
    .filter(([path, stats]) => {
      const coverage = (stats.count - stats.nullCount) / stats.count;
      return (
        coverage > 0.8 &&
        !embeddingPaths.some((ep) => path.startsWith(ep) || ep.startsWith(path))
      );
    })
    .filter(([path]) => !path.includes("[]")) // Skip array details
    .slice(0, 30);

  for (const [path, stats] of unusedHighCoverage) {
    const coverage = (
      ((stats.count - stats.nullCount) / stats.count) *
      100
    ).toFixed(0);
    const unique = stats.uniqueValues.size;
    if (unique > 1 && unique < 50) {
      // Interesting cardinality
      console.log(`${path}: ${coverage}% coverage, ${unique} unique values`);
    }
  }
}

main().catch(console.error);
