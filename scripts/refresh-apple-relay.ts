#!/usr/bin/env npx tsx
/**
 * Refresh Apple Private Relay egress-range list from Apple's authoritative
 * source (mask-api.icloud.com/egress-ip-ranges.csv) and upload a compact,
 * gzipped JSON to the IP_CLASS_BUCKET for the ingestion Lambda to load.
 *
 * Run manually after deploy:
 *   IP_CLASS_BUCKET=ms-argus-api-dev-jw-ip-class-...  npx tsx scripts/refresh-apple-relay.ts
 *
 * Or schedule via EventBridge / cron once the IAM / packaging is set up.
 */
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { gzipSync } from "node:zlib";

const SOURCE_URL = "https://mask-api.icloud.com/egress-ip-ranges.csv";
const S3_KEY = "apple-private-relay-ranges.json.gz";

interface Entry {
  cidr: string;
  country?: string;
  region?: string;
  city?: string;
}

function parseCsv(text: string): Entry[] {
  const out: Entry[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const parts = t.split(",");
    const cidr = parts[0]?.trim();
    if (!cidr || !cidr.includes("/")) continue;
    const country = parts[1]?.trim();
    const region = parts[2]?.trim();
    const city = parts[3]?.trim();
    out.push({
      cidr,
      ...(country ? { country } : {}),
      ...(region ? { region } : {}),
      ...(city ? { city } : {}),
    });
  }
  return out;
}

async function main(): Promise<void> {
  const bucket = process.env.IP_CLASS_BUCKET;
  if (!bucket) {
    throw new Error("IP_CLASS_BUCKET env var required");
  }

  console.log(`fetching ${SOURCE_URL} ...`);
  const res = await fetch(SOURCE_URL);
  if (!res.ok) {
    throw new Error(`failed to fetch: ${res.status} ${res.statusText}`);
  }
  const text = await res.text();
  const rules = parseCsv(text);
  console.log(`parsed ${rules.length} CIDR entries`);

  const payload = {
    generated_at: new Date().toISOString(),
    source_url: SOURCE_URL,
    rules_total: rules.length,
    rules,
  };
  const json = JSON.stringify(payload);
  const gz = gzipSync(Buffer.from(json, "utf-8"));
  console.log(
    `compressed ${json.length} bytes -> ${gz.length} bytes (gzip), uploading to s3://${bucket}/${S3_KEY}`,
  );

  const s3 = new S3Client({});
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: S3_KEY,
      Body: gz,
      ContentType: "application/json",
      ContentEncoding: "gzip",
    }),
  );
  console.log("ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
