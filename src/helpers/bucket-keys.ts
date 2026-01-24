// src/helpers/bucket-keys.ts
// Shared bucket key utilities for matching and profile services
// Single source of truth for Tier 2 bucket key generation

import { fnv1a } from "./hash";
import { SIMHASH_CONFIG } from "./constants";
import type { Fingerprint } from "../types/fingerprint";
import type { EvidenceCode } from "../types/matching";

/**
 * Bucket key info with evidence code for match tracking
 */
export interface BucketKeyInfo {
  key: string;
  evidenceCode: EvidenceCode;
}

interface BucketDef {
  prefix: string;
  fields: (keyof Fingerprint)[];
  evidenceCode: EvidenceCode;
}

const BUCKET_DEFS: BucketDef[] = [
  {
    prefix: "ip_ja4",
    fields: ["ip_address", "ja4"],
    evidenceCode: "IP_JA4_BUCKET",
  },
  {
    prefix: "gpu_screen_tz",
    fields: ["gpu_renderer", "screen_dims", "timezone"],
    evidenceCode: "GPU_SCREEN_TZ_BUCKET",
  },
  {
    prefix: "audio_canvas",
    fields: ["audio_hash", "canvas_hash"],
    evidenceCode: "AUDIO_CANVAS_BUCKET",
  },
  {
    prefix: "maths_window",
    fields: ["maths_hash", "window_features_hash"],
    evidenceCode: "MATHS_WINDOW_BUCKET",
  },
  {
    prefix: "html_css",
    fields: ["html_element_hash", "css_hash"],
    evidenceCode: "HTML_CSS_BUCKET",
  },
  {
    prefix: "webgl_struct",
    fields: ["webgl_hash", "webgl_extensions_count", "svg_hash"],
    evidenceCode: "WEBGL_STRUCT_BUCKET",
  },
];

/**
 * Build compound bucket keys with their evidence code types
 * Used for Tier 2 matching and evidence tracking
 */
export function buildBucketKeysWithTypes(
  fingerprint: Fingerprint,
): BucketKeyInfo[] {
  const buckets: BucketKeyInfo[] = [];

  for (const def of BUCKET_DEFS) {
    const values = def.fields.map((f) => fingerprint[f]);
    if (values.every((v) => v !== undefined && v !== null && v !== "")) {
      buckets.push({
        key: `${def.prefix}#${values.join("#")}`,
        evidenceCode: def.evidenceCode,
      });
    }
  }

  return buckets;
}

/**
 * Build compound bucket keys for Tier 2 matching
 * Returns just the key strings without evidence codes
 */
export function buildBucketKeys(fingerprint: Fingerprint): string[] {
  return buildBucketKeysWithTypes(fingerprint).map((info) => info.key);
}

/**
 * Build session anchor bucket key for ephemeral matching
 * Combines IP + User-Agent hash + Screen dimensions
 * Returns null if required signals are missing
 */
export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  if (
    !fingerprint.ip_address ||
    !fingerprint.user_agent ||
    !fingerprint.screen_dims
  ) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `session_anchor#${fingerprint.ip_address}#${uaHash}#${fingerprint.screen_dims}`;
}

/**
 * Build IP+UA-only anchor bucket key for ephemeral matching
 * Does NOT include screen_dims - catches dock/undock screen changes
 * Returns null if required signals are missing
 */
export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  if (!fingerprint.ip_address || !fingerprint.user_agent) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `ip_ua_anchor#${fingerprint.ip_address}#${uaHash}`;
}

// ==================== SIMHASH LSH BAND KEYS (Tier 1.5) ====================

/**
 * SimHash band key info for LSH indexing
 */
export interface SimHashBandKey {
  /** Full partition key: SIMHASH_BAND#<band_index>#<band_value_hex> */
  pk: string;
  /** Band index (0-3 for 4 bands) */
  bandIndex: number;
  /** Band value as hex string */
  bandValue: string;
}

/**
 * Build SimHash LSH band keys from fuzzy_hash
 * Splits 64-bit hash into 4 bands of 16 bits each for locality-sensitive lookup.
 *
 * Band partitioning allows similar hashes (small Hamming distance) to share
 * at least one band with high probability, enabling efficient candidate retrieval.
 *
 * @param fuzzyHash - 64-bit SimHash as hex string (e.g., "0x1234567890abcdef" or "1234567890abcdef")
 * @returns Array of 4 band keys, or null if fuzzy_hash is invalid
 */
export function buildSimHashBandKeys(
  fuzzyHash: string | undefined,
): SimHashBandKey[] | null {
  if (!fuzzyHash) return null;

  // Normalize: remove 0x prefix if present, ensure lowercase
  const normalized = fuzzyHash.replace(/^0x/i, "").toLowerCase();

  // Validate: must be 16 hex chars (64 bits)
  if (!/^[0-9a-f]{16}$/.test(normalized)) {
    return null;
  }

  const bands: SimHashBandKey[] = [];

  // Split into 4 bands of 4 hex chars (16 bits) each
  for (let i = 0; i < SIMHASH_CONFIG.NUM_BANDS; i++) {
    const startChar = i * 4; // Each band is 4 hex chars
    const bandValue = normalized.slice(startChar, startChar + 4);

    bands.push({
      pk: `SIMHASH_BAND#${i}#${bandValue}`,
      bandIndex: i,
      bandValue,
    });
  }

  return bands;
}

/**
 * Build sort key for SimHash band entry with recency ordering
 * Format: t#<inverted_timestamp>#<device_id>
 *
 * Using inverted timestamp ensures that Query with LIMIT returns
 * the most recent entries first (since DynamoDB sorts SK ascending).
 *
 * @param deviceId - The device ID
 * @param timestamp - Unix timestamp in seconds (defaults to now)
 * @returns Sort key string
 */
export function buildSimHashBandSK(
  deviceId: string,
  timestamp: number = Math.floor(Date.now() / 1000),
): string {
  // Invert timestamp: MAX_SAFE_INTEGER - timestamp
  // This ensures newest entries sort first (smallest SK values)
  const invertedTs = (9999999999999 - timestamp).toString().padStart(13, "0");
  return `t#${invertedTs}#${deviceId}`;
}

/**
 * Parse device ID from SimHash band sort key
 * @param sk - Sort key in format t#<inverted_timestamp>#<device_id>
 * @returns Device ID or null if invalid format
 */
export function parseSimHashBandSK(sk: string): {
  deviceId: string;
  timestamp: number;
} | null {
  const match = sk.match(/^t#(\d{13})#(.+)$/);
  if (!match) return null;

  const invertedTs = parseInt(match[1], 10);
  const timestamp = 9999999999999 - invertedTs;
  return {
    deviceId: match[2],
    timestamp,
  };
}
