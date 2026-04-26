/**
 * IP classification dataset builder.
 *
 * Pulls the public IPtoASN BGP-derived dataset, runs each ASN's organization
 * name through a regex categorizer, applies manual overrides for ASNs whose
 * names don't pattern-match cleanly, and uploads the resulting
 * `asn-categories.json.gz` to the IP_CLASS_BUCKET.
 *
 * Runtime Lambdas (matching workers, ingestion handlers) consume the file
 * via S3 GetObject on cold start to map an ASN number → category bucket
 * (mobile / residential / datacenter / vpn_proxy / etc.) without a network
 * call per request.
 *
 * Cadence: weekly EventBridge schedule + on-deploy custom-resource invoke
 * so the bucket is seeded the first time the stack is created.
 */
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync, gzipSync } from "node:zlib";
import { ASN_OVERRIDES } from "../services/network/asn-overrides";
import { categorize } from "../services/network/categorize";

const IPTOASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";

async function fetchAndDecompress(url: string): Promise<string> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(60_000),
    headers: { "user-agent": "ms-argus-api ip-class-builder" },
  });
  if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  return gunzipSync(buf).toString("utf-8");
}

interface BuildResult {
  asnsTotal: number;
  asnsClassified: number;
  bytesUploaded: number;
  bucket: string;
  key: string;
}

function parseAsnTable(tsv: string): Map<number, string> {
  const asnToOrg = new Map<number, string>();
  for (const line of tsv.split("\n")) {
    const parts = line.split("\t");
    if (parts.length < 5) continue;
    const asn = Number(parts[2]);
    if (!Number.isFinite(asn) || asn === 0) continue;
    const org = parts[4];
    const existing = asnToOrg.get(asn) ?? "";
    if (org.length > existing.length) asnToOrg.set(asn, org);
  }
  return asnToOrg;
}

function buildClassificationDict(
  asnToOrg: Map<number, string>,
): Record<string, string> {
  const asns: Record<string, string> = {};
  for (const [asn, org] of asnToOrg) {
    const cat = categorize(org);
    if (cat) asns[String(asn)] = cat;
  }
  for (const [asn, cat] of Object.entries(ASN_OVERRIDES)) asns[asn] = cat;
  return asns;
}

export async function handler(): Promise<BuildResult> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.IP_CLASS_KEY ?? "asn-categories.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  const tsv = await fetchAndDecompress(IPTOASN_URL);
  const asnToOrg = parseAsnTable(tsv);
  const asns = buildClassificationDict(asnToOrg);

  const payload = {
    generated_at: new Date().toISOString(),
    source: IPTOASN_URL,
    asns_total: asnToOrg.size,
    asns_classified: Object.keys(asns).length,
    asns,
  };
  const gz = gzipSync(Buffer.from(JSON.stringify(payload)), { level: 9 });

  const s3 = new S3Client({});
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: gz,
      ContentEncoding: "gzip",
      ContentType: "application/json",
      CacheControl: "max-age=86400",
    }),
  );

  return {
    asnsTotal: asnToOrg.size,
    asnsClassified: Object.keys(asns).length,
    bytesUploaded: gz.length,
    bucket,
    key,
  };
}
