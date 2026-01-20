// src/helpers/bucket-keys.ts
// AR-117: Shared bucket key utilities for matching and profile services
// Single source of truth for Tier 2 bucket key generation
// AR-XXX: Added SimHash LSH band key generation for Tier 1.5

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

/**
 * Build compound bucket keys with their evidence code types
 * Used for Tier 2 matching and evidence tracking
 */
export function buildBucketKeysWithTypes(
  fingerprint: Fingerprint,
): BucketKeyInfo[] {
  const buckets: BucketKeyInfo[] = [];

  // IP + JA4 (network identity)
  if (fingerprint.ip_address && fingerprint.ja4) {
    buckets.push({
      key: `ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`,
      evidenceCode: "IP_JA4_BUCKET",
    });
  }

  // GPU + Screen + Timezone (hardware/locale identity)
  if (
    fingerprint.gpu_renderer &&
    fingerprint.screen_dims &&
    fingerprint.timezone
  ) {
    buckets.push({
      key: `gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`,
      evidenceCode: "GPU_SCREEN_TZ_BUCKET",
    });
  }

  // Audio + Canvas (rendering identity)
  if (fingerprint.audio_hash && fingerprint.canvas_hash) {
    buckets.push({
      key: `audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`,
      evidenceCode: "AUDIO_CANVAS_BUCKET",
    });
  }

  // AR-80: Structural tier2 buckets (stable browser engine anchors)
  // These signals are based on browser internals that cannot be randomized
  // without breaking website functionality. Useful when canvas/audio are
  // blocked (e.g., Brave private browsing).

  // Maths + WindowFeatures (FPU + browser engine signals)
  if (fingerprint.maths_hash && fingerprint.window_features_hash) {
    buckets.push({
      key: `maths_window#${fingerprint.maths_hash}#${fingerprint.window_features_hash}`,
      evidenceCode: "MATHS_WINDOW_BUCKET",
    });
  }

  // HtmlElement + CSS (DOM/CSS capabilities)
  if (fingerprint.html_element_hash && fingerprint.css_hash) {
    buckets.push({
      key: `html_css#${fingerprint.html_element_hash}#${fingerprint.css_hash}`,
      evidenceCode: "HTML_CSS_BUCKET",
    });
  }

  // WebGL + Extensions + SVG (rendering capabilities)
  if (
    fingerprint.webgl_hash &&
    fingerprint.webgl_extensions_count !== undefined &&
    fingerprint.svg_hash
  ) {
    buckets.push({
      key: `webgl_struct#${fingerprint.webgl_hash}#${fingerprint.webgl_extensions_count}#${fingerprint.svg_hash}`,
      evidenceCode: "WEBGL_STRUCT_BUCKET",
    });
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
 * Alias for buildBucketKeys - used by profile-service
 * Maintains naming compatibility during refactor
 */
export const buildTier2BucketKeys = buildBucketKeys;

/**
 * AR-82: Build session anchor bucket key for ephemeral matching
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
 * AR-94: Build IP+UA-only anchor bucket key for ephemeral matching
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
 * AR-XXX: Build SimHash LSH band keys from fuzzy_hash
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
 * AR-XXX: Build sort key for SimHash band entry with recency ordering
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
 * AR-XXX: Parse device ID from SimHash band sort key
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

/**
 * AR-XXX: Calculate Hamming distance between two 64-bit hex hashes
 * Counts the number of differing bits between two SimHash values.
 *
 * @param hash1 - First hash as hex string
 * @param hash2 - Second hash as hex string
 * @returns Number of differing bits (0-64), or -1 if invalid
 */
export function hammingDistance(hash1: string, hash2: string): number {
  // Normalize
  const h1 = hash1.replace(/^0x/i, "").toLowerCase();
  const h2 = hash2.replace(/^0x/i, "").toLowerCase();

  if (!/^[0-9a-f]{16}$/.test(h1) || !/^[0-9a-f]{16}$/.test(h2)) {
    return -1;
  }

  let distance = 0;

  // Process 4 chars (16 bits) at a time to stay within JS safe integer range
  for (let i = 0; i < 16; i += 4) {
    const chunk1 = parseInt(h1.slice(i, i + 4), 16);
    const chunk2 = parseInt(h2.slice(i, i + 4), 16);
    const xor = chunk1 ^ chunk2;
    // Count set bits (Brian Kernighan's algorithm)
    let bits = xor;
    while (bits) {
      distance++;
      bits &= bits - 1;
    }
  }

  return distance;
}
