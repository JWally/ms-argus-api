/**
 * Auto-overlay loader.
 *
 * Reads `auto-overlay.json.gz` from the IP_CLASS_BUCKET on Lambda cold
 * start, compiles it into a sorted CIDR range list, caches in module
 * scope. Refreshes every 24h.
 *
 * Same usage shape as asn-classifier.ts — call `prewarmAutoOverlay()`
 * once per request, then `lookupAutoOverlay(ip)` is sync and <1µs.
 *
 * The overlay file is produced by the ip-class-discoverer Lambda nightly:
 * each entry is { cidr, category, name, source: 'rdap_ip'|'rdap_search',
 * discovered_at }. The discoverer dedupes and merges with prior state so
 * the file grows monotonically (capped by the discoverer's rule TTL/
 * cleanup logic if added later).
 */
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { gunzipSync } from "node:zlib";
import {
  compileCidrList,
  lookupInRanges,
  type CompiledRange,
} from "./cidr-tree";
import type { NetworkCategory } from "./categorize";

interface OverlayEntryWire {
  cidr: string;
  category: NetworkCategory;
  name: string;
  source?: string;
  discovered_at?: string;
  /** New fields added 2026-05 — optional so existing S3 files (pre-enrichment)
   *  still deserialize. The discoverer backfills these on next nightly walk. */
  customer_org?: string;
  parent_org?: string;
  parent_cidr?: string;
}

interface OverlayMeta {
  name: string;
  customerOrg?: string;
  parentOrg?: string;
  parentCidr?: string;
}

interface OverlayFileShape {
  generated_at: string;
  rules_total: number;
  rules: OverlayEntryWire[];
}

const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;
let cached: readonly CompiledRange<OverlayMeta>[] | null = null;
let cachedAt = 0;
let inflight: Promise<readonly CompiledRange<OverlayMeta>[]> | null = null;
const s3 = new S3Client({});

async function loadOverlay(): Promise<readonly CompiledRange<OverlayMeta>[]> {
  const bucket = process.env.IP_CLASS_BUCKET;
  const key = process.env.IP_CLASS_AUTO_OVERLAY_KEY ?? "auto-overlay.json.gz";
  if (!bucket) throw new Error("IP_CLASS_BUCKET env var is required");

  try {
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
    );
    if (!obj.Body) return [];
    const buf = Buffer.from(await obj.Body.transformToByteArray());
    const parsed = JSON.parse(
      gunzipSync(buf).toString("utf-8"),
    ) as OverlayFileShape;
    return compileCidrList(
      parsed.rules.map((r) => ({
        cidr: r.cidr,
        category: r.category,
        meta: {
          name: r.name,
          ...(r.customer_org ? { customerOrg: r.customer_org } : {}),
          ...(r.parent_org ? { parentOrg: r.parent_org } : {}),
          ...(r.parent_cidr ? { parentCidr: r.parent_cidr } : {}),
        },
      })),
    );
  } catch {
    // Missing file (first deploy before discoverer has run) is fine —
    // return empty. classifier falls through to next layer.
    return [];
  }
}

async function getOverlay(): Promise<readonly CompiledRange<OverlayMeta>[]> {
  if (cached && Date.now() - cachedAt < REFRESH_INTERVAL_MS) return cached;
  if (inflight) return inflight;
  inflight = loadOverlay().then((data) => {
    cached = data;
    cachedAt = Date.now();
    inflight = null;
    return data;
  });
  return inflight;
}

/**
 * Synchronous lookup. Caller must have called `prewarmAutoOverlay` first
 * (the ingestion handler does this in parallel with prewarmAsnDataset).
 * Returns null when the IP isn't in any auto-discovered rule (caller
 * should fall through to the ASN dict / legacy catalog).
 */
export function lookupAutoOverlaySync(ip: string): {
  category: NetworkCategory;
  name: string;
  customerOrg?: string;
  parentOrg?: string;
  parentCidr?: string;
} | null {
  if (!cached) return null;
  const hit = lookupInRanges(cached, ip);
  if (!hit) return null;
  const meta = hit.meta as OverlayMeta | undefined;
  return {
    category: hit.category,
    name: meta?.name ?? "",
    ...(meta?.customerOrg ? { customerOrg: meta.customerOrg } : {}),
    ...(meta?.parentOrg ? { parentOrg: meta.parentOrg } : {}),
    ...(meta?.parentCidr ? { parentCidr: meta.parentCidr } : {}),
  };
}

/** Trigger an overlay load if not already cached. */
export async function prewarmAutoOverlay(): Promise<void> {
  await getOverlay();
}

/** Test/debug: clear the in-memory cache so a unit test can re-seed. */
export function _resetAutoOverlayForTesting(): void {
  cached = null;
  cachedAt = 0;
  inflight = null;
}

/** Test/debug: seed the in-memory overlay from a list of raw rules. */
export function _seedAutoOverlayForTesting(
  rules: {
    cidr: string;
    category: NetworkCategory;
    name: string;
    customerOrg?: string;
    parentOrg?: string;
    parentCidr?: string;
  }[],
): void {
  cached = compileCidrList(
    rules.map((r) => ({
      cidr: r.cidr,
      category: r.category,
      meta: {
        name: r.name,
        ...(r.customerOrg ? { customerOrg: r.customerOrg } : {}),
        ...(r.parentOrg ? { parentOrg: r.parentOrg } : {}),
        ...(r.parentCidr ? { parentCidr: r.parentCidr } : {}),
      },
    })),
  );
  cachedAt = Date.now();
  inflight = null;
}
