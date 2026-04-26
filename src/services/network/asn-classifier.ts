/**
 * Runtime ASN classifier.
 *
 * Loads the ASN→category dataset from S3 (built weekly by ip-class-builder
 * Lambda) on Lambda cold start, caches in module scope (so warm invocations
 * are free), refreshes lazily once per day.
 *
 * Lookup is a hash-map get: O(1), <1µs. No network call per request.
 *
 * For mixed-use ASNs (notably AT&T 7018 — both U-Verse residential and AT&T
 * Mobility cellular live on the same ASN), the dataset returns "unknown" and
 * the caller should fall through to a CIDR-based sub-allocation overlay. See
 * the integrity-archive empirical validation in `__ideas__/asn-classifier.md`.
 */
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync } from "node:zlib";
import type { NetworkCategory as BaseNetworkCategory } from "./categorize";

/**
 * Re-export so existing import paths (`from "./asn-classifier"`) still work.
 * Adds `"unknown"` for callers that need to model dataset misses as a string
 * value rather than a null fallthrough.
 */
export type NetworkCategory = BaseNetworkCategory | "unknown";

interface DatasetPayload {
  generated_at: string;
  source: string;
  asns_total: number;
  asns_classified: number;
  asns: Record<string, NetworkCategory>;
}

const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
let cached: Record<string, NetworkCategory> | null = null;
let cachedAt = 0;
let inflight: Promise<Record<string, NetworkCategory>> | null = null;
const s3 = new S3Client({});

async function loadDataset(): Promise<Record<string, NetworkCategory>> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.IP_CLASS_KEY ?? "asn-categories.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (!obj.Body) throw new Error(`empty body for s3://${bucket}/${key}`);
  const buf = Buffer.from(await obj.Body.transformToByteArray());
  const json = JSON.parse(gunzipSync(buf).toString("utf-8")) as DatasetPayload;
  return json.asns;
}

async function getDataset(): Promise<Record<string, NetworkCategory>> {
  if (cached && Date.now() - cachedAt < REFRESH_INTERVAL_MS) return cached;
  if (inflight) return inflight;
  inflight = loadDataset().then((data) => {
    cached = data;
    cachedAt = Date.now();
    inflight = null;
    return data;
  });
  return inflight;
}

/**
 * Synchronous classifier — call `prewarmAsnDataset()` once per request first
 * (the ingestion handler does this in parallel with identity verification),
 * then call this freely. Returns "unknown" if the ASN isn't in the dataset
 * (either uncategorizable by regex/overrides, or a mixed-use ASN like AT&T
 * 7018 where callers should fall through to a CIDR-based sub-allocation
 * lookup) OR if the dataset hasn't been loaded yet.
 */
export function classifyAsnSync(asn: number): NetworkCategory {
  return cached?.[String(asn)] ?? "unknown";
}

/**
 * Trigger a dataset load if not already cached. Call once per request before
 * any `classifyAsnSync` invocations to guarantee the lookup table is in
 * memory. After the first cold-start fetch (~50–100 ms), subsequent calls
 * within the 24h TTL are no-ops.
 */
export async function prewarmAsnDataset(): Promise<void> {
  await getDataset();
}

/** Test/debug hook — clears the in-memory cache to force a reload. */
export function _resetCacheForTesting(): void {
  cached = null;
  cachedAt = 0;
  inflight = null;
}

/**
 * Test-only hook: seed the in-memory dataset directly so unit tests can
 * exercise the dict-priority code path without an S3 round-trip. Tests are
 * expected to call `_resetCacheForTesting()` afterwards to leave a clean
 * state for adjacent tests.
 */
export function _seedCacheForTesting(
  dict: Record<string, NetworkCategory>,
): void {
  cached = dict;
  cachedAt = Date.now();
  inflight = null;
}
