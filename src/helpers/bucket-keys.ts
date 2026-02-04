import { fnv1a } from "./hash";
import { SIMHASH_CONFIG } from "./constants";
import type { Fingerprint } from "../types/fingerprint";

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
 * Splits 256-bit hash into 16 bands of 16 bits each for locality-sensitive lookup.
 *
 * Band partitioning allows similar hashes (small Hamming distance) to share
 * at least one band with high probability, enabling efficient candidate retrieval.
 *
 * @param fuzzyHash - 256-bit SimHash as hex string (64 hex chars)
 * @returns Array of 16 band keys, or null if fuzzy_hash is invalid
 */
export function buildSimHashBandKeys(
  fuzzyHash: string | undefined,
): SimHashBandKey[] | null {
  if (!fuzzyHash) return null;

  const normalized = fuzzyHash.replace(/^0x/i, "").toLowerCase();

  // Accept 256-bit (64 chars) or legacy 64-bit (16 chars)
  if (
    !/^[0-9a-f]{64}$/.test(normalized) &&
    !/^[0-9a-f]{16}$/.test(normalized)
  ) {
    return null;
  }

  const bands: SimHashBandKey[] = [];
  const charsPerBand = SIMHASH_CONFIG.HEX_CHARS_PER_BAND;
  const numBands = normalized.length / charsPerBand;

  for (let i = 0; i < numBands; i++) {
    const startChar = i * charsPerBand;
    const bandValue = normalized.slice(startChar, startChar + charsPerBand);

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
