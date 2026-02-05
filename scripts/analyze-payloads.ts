/**
 * Analyze payload data to evaluate embedding structure
 *
 * Run: npx ts-node scripts/analyze-payloads.ts
 */
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

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

function walkObject(obj: unknown, path = "") {
  if (obj === null || obj === undefined) {
    analyzeValue(path, obj);
    return;
  }

  if (Array.isArray(obj)) {
    analyzeValue(path, `[array:${obj.length}]`);
    // Sample first few elements
    obj.slice(0, 3).forEach((item, idx) => {
      walkObject(item, `${path}[${idx}]`);
    });
    return;
  }

  if (typeof obj === "object") {
    for (const [key, val] of Object.entries(obj)) {
      const newPath = path ? `${path}.${key}` : key;
      if (typeof val === "object" && val !== null && !Array.isArray(val)) {
        walkObject(val, newPath);
      } else {
        analyzeValue(newPath, val);
      }
    }
    return;
  }

  analyzeValue(path, obj);
}

async function main() {
  console.log("Scanning payload table...\n");

  let totalItems = 0;
  let lastKey: Record<string, any> | undefined;

  // Scan up to 100 items
  while (totalItems < 100) {
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
        totalItems++;

        // Analyze the device section (fingerprint data)
        if (unmarshalled.payload?.device) {
          walkObject(unmarshalled.payload.device, "device");
        }

        // Analyze sigint section
        if (unmarshalled.payload?.sigint) {
          walkObject(unmarshalled.payload.sigint, "sigint");
        }

        // Analyze hashes section
        if (unmarshalled.payload?.hashes) {
          walkObject(unmarshalled.payload.hashes, "hashes");
        }

        // Analyze identifiers
        if (unmarshalled.payload?.identifiers) {
          walkObject(unmarshalled.payload.identifiers, "identifiers");
        }
      }
    }

    lastKey = result.LastEvaluatedKey;
    if (!lastKey) break;
  }

  console.log(`Analyzed ${totalItems} payloads\n`);

  // Print analysis
  console.log("=".repeat(80));
  console.log("FIELD ANALYSIS");
  console.log("=".repeat(80));

  // Sort fields by path
  const sortedFields = Object.entries(fieldStats).sort((a, b) =>
    a[0].localeCompare(b[0]),
  );

  // Group by top-level section
  const sections: Record<string, [string, FieldStats][]> = {};
  for (const [path, stats] of sortedFields) {
    const section = path.split(".")[0];
    if (!sections[section]) sections[section] = [];
    sections[section].push([path, stats]);
  }

  for (const [section, fields] of Object.entries(sections)) {
    console.log(`\n## ${section.toUpperCase()}\n`);

    for (const [path, stats] of fields) {
      const coverage = (
        ((stats.count - stats.nullCount) / stats.count) *
        100
      ).toFixed(0);
      const uniqueCount = stats.uniqueValues.size;

      console.log(`${path}`);
      console.log(
        `  Coverage: ${coverage}% (${stats.count - stats.nullCount}/${stats.count})`,
      );
      console.log(
        `  Unique values: ${uniqueCount}${uniqueCount >= 100 ? "+" : ""}`,
      );

      if (stats.numericMin !== undefined) {
        console.log(`  Range: ${stats.numericMin} - ${stats.numericMax}`);
      }

      if (stats.sampleValues.length > 0 && stats.sampleValues[0].length < 60) {
        console.log(`  Samples: ${stats.sampleValues.slice(0, 3).join(", ")}`);
      }
      console.log("");
    }
  }

  // Special analysis: IP addresses
  console.log("=".repeat(80));
  console.log("IP ADDRESS ANALYSIS");
  console.log("=".repeat(80));

  const ipFields = sortedFields.filter(
    ([path]) =>
      path.toLowerCase().includes("ip") ||
      path.includes("reflexiveIp") ||
      path.includes("localIp"),
  );

  for (const [path, stats] of ipFields) {
    console.log(`\n${path}:`);
    console.log(`  Unique IPs: ${stats.uniqueValues.size}`);
    console.log(`  Samples: ${stats.sampleValues.slice(0, 5).join(", ")}`);
  }

  // Embedding quality assessment
  console.log("\n" + "=".repeat(80));
  console.log("EMBEDDING STRUCTURE ASSESSMENT");
  console.log("=".repeat(80));

  const embeddingFields = [
    "device.stable.canvas2d",
    "device.stable.canvasWebgl",
    "device.stable.offlineAudioContext",
    "device.loose.screen",
    "device.loose.navigator",
    "device.loose.headless",
    "sigint.tlsFingerprint",
    "sigint.tcpProbe",
    "hashes.stable",
    "hashes.fuzzy",
  ];

  console.log("\nKey embedding source fields coverage:");
  for (const field of embeddingFields) {
    const matchingFields = sortedFields.filter(([path]) =>
      path.startsWith(field),
    );
    if (matchingFields.length > 0) {
      const maxCoverage = Math.max(
        ...matchingFields.map(([, s]) => (s.count - s.nullCount) / s.count),
      );
      console.log(`  ${field}: ${(maxCoverage * 100).toFixed(0)}% coverage`);
    } else {
      console.log(`  ${field}: NOT FOUND`);
    }
  }
}

main().catch(console.error);
