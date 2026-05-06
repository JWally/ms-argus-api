/**
 * Runtime browser-engine baseline loader.
 *
 * Loads the per-(browser, version, incognito) histograms built daily by
 * `browser-baseline-builder` Lambda. Same loading pattern as
 * `asn-classifier.ts`: S3 GET on Lambda cold start, in-memory cache for
 * 24h, lazy refresh, no per-request network call.
 *
 * Two lookup modes:
 *   - `lookupBrowserBaselineSync(key)` — exact (browser, version[, incognito])
 *     match. e.g. "Chrome 147", "Chrome 147 incognito", "Safari iOS 18.7".
 *   - `lookupEngineFamilyBaselineSync(family)` — fallback union across all
 *     versions of an engine family. Used when the version-specific
 *     baseline is missing (cold start after a new browser version ships)
 *     or has too few samples for hard-break determinations.
 */
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync } from "node:zlib";

export interface FieldHistogram {
  /** value (as string for serialization) → observed count */
  [valueAsString: string]: number;
}

export interface BrowserBaseline {
  n_sessions: number;
  fields: { [field: string]: FieldHistogram };
}

interface BaselinesPayload {
  generated_at: string;
  lookback_hours: number;
  n_total: number;
  n_after_dedup: number;
  browsers: { [key: string]: BrowserBaseline };
  engine_families: { [family: string]: BrowserBaseline };
}

interface CachedBaselines {
  browsers: { [key: string]: BrowserBaseline };
  engine_families: { [family: string]: BrowserBaseline };
  generated_at: string;
}

const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
let cached: CachedBaselines | null = null;
let cachedAt = 0;
let inflight: Promise<CachedBaselines> | null = null;
const s3 = new S3Client({});

async function loadBaselines(): Promise<CachedBaselines> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.BROWSER_BASELINES_KEY ?? "browser-baselines.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  const obj = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (!obj.Body) throw new Error(`empty body for s3://${bucket}/${key}`);
  const buf = Buffer.from(await obj.Body.transformToByteArray());
  const json = JSON.parse(
    gunzipSync(buf).toString("utf-8"),
  ) as BaselinesPayload;
  return {
    browsers: json.browsers ?? {},
    engine_families: json.engine_families ?? {},
    generated_at: json.generated_at,
  };
}

async function getBaselines(): Promise<CachedBaselines> {
  if (cached && Date.now() - cachedAt < REFRESH_INTERVAL_MS) return cached;
  if (inflight) return inflight;
  inflight = loadBaselines().then((data) => {
    cached = data;
    cachedAt = Date.now();
    inflight = null;
    return data;
  });
  return inflight;
}

/**
 * Synchronous lookup. Caller must have called `prewarmBrowserBaselines()`
 * first (the ingestion handler does this in parallel with the other
 * prewarms). Returns null when the key isn't in the cache OR the file
 * hasn't been loaded yet — analyzer treats either case as "skip the
 * check, no signal" so cold start never produces false positives.
 */
export function lookupBrowserBaselineSync(key: string): BrowserBaseline | null {
  return cached?.browsers[key] ?? null;
}

/**
 * Engine-family fallback (chromium / gecko / webkit). Used when the
 * version-specific baseline is missing or too sparse — wider buckets,
 * still catches gross mismatches like "Safari UA + V8 jsEngine".
 */
export function lookupEngineFamilyBaselineSync(
  family: string,
): BrowserBaseline | null {
  return cached?.engine_families[family] ?? null;
}

/** Trigger a baselines load if not already cached. */
export async function prewarmBrowserBaselines(): Promise<void> {
  await getBaselines();
}

/** Test/debug hook — clears the in-memory cache to force a reload. */
export function _resetBrowserBaselinesForTesting(): void {
  cached = null;
  cachedAt = 0;
  inflight = null;
}

/**
 * Test-only hook: seed the in-memory cache directly so unit tests can
 * exercise the analyzer without an S3 round-trip.
 */
export function _seedBrowserBaselinesForTesting(data: {
  browsers?: { [key: string]: BrowserBaseline };
  engine_families?: { [family: string]: BrowserBaseline };
}): void {
  cached = {
    browsers: data.browsers ?? {},
    engine_families: data.engine_families ?? {},
    generated_at: new Date().toISOString(),
  };
  cachedAt = Date.now();
  inflight = null;
}
