/**
 * IP classification dataset builder.
 *
 * Pulls the public IPtoASN BGP-derived dataset, runs each ASN's organization
 * name through a regex categorizer, applies manual overrides for ASNs whose
 * names don't pattern-match cleanly, joins in PeeringDB's operator-self-
 * declared network type as a passive cross-check, and uploads the resulting
 * `asn-categories.json.gz` to the IP_CLASS_BUCKET.
 *
 * Persists three parallel maps:
 *   - `asns`:       ASN → category string (mobile / residential / datacenter / ...).
 *                   Only ASNs the regex categorizer recognized + manual overrides.
 *   - `orgs`:       ASN → organization name (raw IPtoASN value, max-length per ASN
 *                   when the same ASN appears in multiple rows). Stored for ALL
 *                   ASNs in the dataset, not just categorized ones, so the merchant
 *                   projection can surface a human-readable network name on rows
 *                   whose ASN isn't in the small static catalog (`asn-catalog.ts`).
 *   - `pdb_types`:  ASN → { info_type, ix_count } from PeeringDB. Operator-self-
 *                   declared, useful for cross-checking the regex (e.g., regex says
 *                   "datacenter" but PeeringDB says "Cable/DSL/ISP" → flag). Absent
 *                   when PeeringDB has no record for that ASN. Empty map when the
 *                   PeeringDB fetch failed — build still succeeds without it.
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
import {
  fetchPeeringDbTypes,
  type PdbInfo,
} from "../services/network/peeringdb-client";

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
  asnsWithOrg: number;
  asnsWithPdb: number;
  pdbMismatches: number;
  bytesUploaded: number;
  bucket: string;
  key: string;
}

/** Coarse mapping of our regex categories → the families PeeringDB declares.
 *  Used only for mismatch logging — never to override a category. A return
 *  value of `null` means "we shouldn't expect agreement here" (e.g., we
 *  tagged the ASN as a mobile carrier; PeeringDB doesn't have a dedicated
 *  cellular type), so the comparison is skipped.
 *
 *  Disagreements that DO surface (datacenter regex hit vs Cable/DSL/ISP
 *  declared, etc.) are flagged in build output for human review on the
 *  next regex sweep. */
function expectedPdbFamily(category: string): string[] | null {
  switch (category) {
    case "datacenter":
    case "hosting_proxy":
    case "vpn_proxy":
      return ["NSP", "Content", "Network Services"];
    case "residential":
      return ["Cable/DSL/ISP", "NSP"];
    case "cdn":
      return ["Content", "NSP"];
    case "education":
      return ["Educational"];
    case "government":
      return ["Government"];
    case "business":
      return ["Enterprise", "NSP", "Cable/DSL/ISP"];
    default:
      // mobile, satellite, privacy_relay, security_filter, cdn-edge —
      // PeeringDB type isn't a useful comparator for these.
      return null;
  }
}

function buildPdbTypesDict(
  pdb: Map<number, PdbInfo>,
): Record<string, { info_type: string; ix_count: number }> {
  const out: Record<string, { info_type: string; ix_count: number }> = {};
  for (const [asn, info] of pdb) {
    out[String(asn)] = info;
  }
  return out;
}

function countMismatches(
  asns: Record<string, string>,
  pdb: Map<number, PdbInfo>,
): number {
  let mismatches = 0;
  for (const [asn, category] of Object.entries(asns)) {
    const pdbEntry = pdb.get(Number(asn));
    if (!pdbEntry || pdbEntry.info_type === "") continue;
    const expected = expectedPdbFamily(category);
    if (!expected) continue;
    if (!expected.includes(pdbEntry.info_type)) {
      mismatches += 1;
    }
  }
  return mismatches;
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

/**
 * Persist the org name for every ASN in the dataset (not just categorized
 * ones). Trims whitespace and skips empty values; otherwise raw IPtoASN
 * value. The static catalog (asn-catalog.ts) provides cleaner names for
 * a hand-curated subset and wins at lookup time — this is the long-tail
 * fallback so the merchant projection can show *something* for residential
 * ISPs the static catalog doesn't list (AT&T 7018, Comcast 7922, etc.).
 */
function buildOrgsDict(asnToOrg: Map<number, string>): Record<string, string> {
  const orgs: Record<string, string> = {};
  for (const [asn, org] of asnToOrg) {
    const trimmed = org.trim();
    if (trimmed.length > 0) orgs[String(asn)] = trimmed;
  }
  return orgs;
}

interface BuiltDataset {
  asnToOrg: Map<number, string>;
  asns: Record<string, string>;
  orgs: Record<string, string>;
  pdb_types: Record<string, { info_type: string; ix_count: number }>;
  pdbMismatches: number;
}

async function buildDataset(): Promise<BuiltDataset> {
  // Kick off both fetches in parallel — they're independent. PeeringDB is
  // the slower of the two; running them concurrently shaves ~3s.
  const [tsv, pdbTypes] = await Promise.all([
    fetchAndDecompress(IPTOASN_URL),
    fetchPeeringDbTypes(),
  ]);
  const asnToOrg = parseAsnTable(tsv);
  const asns = buildClassificationDict(asnToOrg);
  const orgs = buildOrgsDict(asnToOrg);
  const pdb_types = buildPdbTypesDict(pdbTypes);
  const pdbMismatches = countMismatches(asns, pdbTypes);
  if (pdbMismatches > 0) {
    console.log(
      JSON.stringify({
        msg: "pdb_regex_mismatch_summary",
        count: pdbMismatches,
        note: "regex category disagrees with PeeringDB info_type — review categorize.ts",
      }),
    );
  }
  return { asnToOrg, asns, orgs, pdb_types, pdbMismatches };
}

async function uploadPayload(
  bucket: string,
  key: string,
  d: BuiltDataset,
): Promise<number> {
  const payload = {
    generated_at: new Date().toISOString(),
    source: IPTOASN_URL,
    asns_total: d.asnToOrg.size,
    asns_classified: Object.keys(d.asns).length,
    asns_with_org: Object.keys(d.orgs).length,
    asns_with_pdb: Object.keys(d.pdb_types).length,
    pdb_mismatches: d.pdbMismatches,
    asns: d.asns,
    orgs: d.orgs,
    pdb_types: d.pdb_types,
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
  return gz.length;
}

export async function handler(): Promise<BuildResult> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.IP_CLASS_KEY ?? "asn-categories.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  const d = await buildDataset();
  const bytesUploaded = await uploadPayload(bucket, key, d);

  return {
    asnsTotal: d.asnToOrg.size,
    asnsClassified: Object.keys(d.asns).length,
    asnsWithOrg: Object.keys(d.orgs).length,
    asnsWithPdb: Object.keys(d.pdb_types).length,
    pdbMismatches: d.pdbMismatches,
    bytesUploaded,
    bucket,
    key,
  };
}
