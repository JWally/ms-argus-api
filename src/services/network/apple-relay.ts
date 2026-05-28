/**
 * Apple iCloud Private Relay egress lookup.
 *
 * Authoritative source: `https://mask-api.icloud.com/egress-ip-ranges.csv`
 * (Apple Developer documentation:
 * https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/).
 * Apple publishes the complete list of egress CIDRs for Private Relay traffic;
 * a request whose source IP is in that list provably originated from an Apple
 * device running iOS 15+ / iPadOS 15+ / macOS Monterey+ with an iCloud+
 * subscription (the OS-level relay daemon is not available on other
 * platforms, so the source can't be anything else).
 *
 * The list is the **ground truth** for verifying Apple-platform identity at
 * the network layer — stronger than a PAT inference, because a missing PAT
 * can be an issuer/network hiccup but a CIDR membership is unambiguous.
 *
 * Loading: same pattern as auto-overlay.ts — fetch the gzipped JSON from
 * `IP_CLASS_BUCKET` at Lambda cold start, compile to a sorted uint32 range
 * list, cache 24h. Refresh job (scripts/refresh-apple-relay.ts) downloads
 * Apple's CSV and writes the gzipped JSON to S3 on a schedule.
 *
 * Graceful degradation: a missing S3 object (first deploy, refresh job
 * hasn't run) returns an empty list. Lookups all return false, and the
 * pre-existing JA4-based `isVerifiedAppleRelay` heuristic still runs.
 */
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync } from "node:zlib";
import {
  compileCidrList,
  lookupInRanges,
  type CompiledRange,
} from "./cidr-tree";

interface AppleRelayEntryWire {
  cidr: string;
  /** ISO 3166-1 country code from Apple's CSV (col 2). */
  country?: string;
  /** ISO 3166-2 subdivision code (col 3). */
  region?: string;
  /** City name (col 4). */
  city?: string;
}

interface AppleRelayMeta {
  country?: string;
  region?: string;
  city?: string;
}

interface AppleRelayFileShape {
  generated_at: string;
  source_url: string;
  rules_total: number;
  rules: AppleRelayEntryWire[];
}

const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
let cached: readonly CompiledRange<AppleRelayMeta>[] | null = null;
let cachedAt = 0;
let inflight: Promise<readonly CompiledRange<AppleRelayMeta>[]> | null = null;
const s3 = new S3Client({});

async function loadAppleRelay(): Promise<
  readonly CompiledRange<AppleRelayMeta>[]
> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key =
    process.env.APPLE_RELAY_KEY ?? "apple-private-relay-ranges.json.gz";
  if (!bucket) return [];

  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) return [];
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    const parsed = JSON.parse(
      gunzipSync(buf).toString("utf-8"),
    ) as AppleRelayFileShape;
    return compileCidrList(
      parsed.rules.map((r) => ({
        cidr: r.cidr,
        category: "privacy_relay",
        meta: {
          ...(r.country ? { country: r.country } : {}),
          ...(r.region ? { region: r.region } : {}),
          ...(r.city ? { city: r.city } : {}),
        },
      })),
    );
  } catch {
    // Missing file (first deploy before refresh job has run) is fine —
    // return empty. The pre-existing JA4 heuristic in
    // isVerifiedAppleRelay still works for the most common cases.
    return [];
  }
}

async function getAppleRelay(): Promise<
  readonly CompiledRange<AppleRelayMeta>[]
> {
  if (cached && Date.now() - cachedAt < REFRESH_INTERVAL_MS) return cached;
  if (inflight) return inflight;
  inflight = loadAppleRelay().then((data) => {
    cached = data;
    cachedAt = Date.now();
    inflight = null;
    return data;
  });
  return inflight;
}

/**
 * Synchronous lookup. Returns true iff the IP is in Apple's published
 * Private Relay egress range. Caller must have called
 * `prewarmAppleRelay()` first (the ingestion handler does this in the
 * parallel prewarm block alongside ASN dataset and auto-overlay).
 *
 * Empty cache (S3 fetch failure or no refresh yet) returns false rather
 * than throwing — degrades to "carve-out not applied," which is the
 * conservative behavior.
 */
export function lookupAppleRelaySync(ip: string): {
  country?: string;
  region?: string;
  city?: string;
} | null {
  if (!cached) return null;
  const hit = lookupInRanges(cached, ip);
  if (!hit) return null;
  return (hit.meta as AppleRelayMeta | undefined) ?? {};
}

/** True/false convenience wrapper. */
export function isAppleRelayIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  return lookupAppleRelaySync(ip) !== null;
}

/** Trigger a load if not already cached. Call once per request from
 *  ingestion handler. Same shape as prewarmAutoOverlay. */
export async function prewarmAppleRelay(): Promise<void> {
  await getAppleRelay();
}

/** Test/debug: clear cache. */
export function _resetAppleRelayForTesting(): void {
  cached = null;
  cachedAt = 0;
  inflight = null;
}

/** Test/debug: seed from a raw rule list. */
export function _seedAppleRelayForTesting(
  rules: { cidr: string; country?: string; region?: string; city?: string }[],
): void {
  cached = compileCidrList(
    rules.map((r) => ({
      cidr: r.cidr,
      category: "privacy_relay",
      meta: {
        ...(r.country ? { country: r.country } : {}),
        ...(r.region ? { region: r.region } : {}),
        ...(r.city ? { city: r.city } : {}),
      },
    })),
  );
  cachedAt = Date.now();
  inflight = null;
}
