/**
 * PostgreSQL query layer for unified T1/T1.5 fingerprint matching.
 *
 * Uses a single `device_hashes` table: one row per device, one query
 * covers both stable-hash exact match (T1) and SimHash LSH (T1.5).
 *
 * @module services/postgres/queries
 */

import type { Pool } from "pg";
import { Logger } from "@aws-lambda-powertools/logger";
import { hammingDistance, computeFuzzyMatchInfo } from "../../helpers/hash";
import { SIMHASH_CONFIG } from "../../helpers/constants";
import { MatchTier } from "../../types/matching-tiers";
import type {
  Fingerprint,
  MatchResult,
  PgQueryContext,
} from "../matching/types";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "postgres-queries",
});

// ============================================================================
// Helpers: Bit/Hex Conversion
// ============================================================================

/** Convert a hex string to a binary string for BIT(256) parameter. */
function hexToBitString(hex: string): string {
  return hex
    .replace(/^0x/i, "")
    .toLowerCase()
    .split("")
    .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
    .join("");
}

/** Convert a PostgreSQL BIT string back to hex. */
function bitStringToHex(bitStr: string): string {
  let hex = "";
  for (let i = 0; i < bitStr.length; i += 4) {
    hex += parseInt(bitStr.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

/** Extract a 16-bit band from a normalized hex hash as a binary string. */
function extractBand(normalizedHex: string, bandIndex: number): string {
  const start = bandIndex * SIMHASH_CONFIG.HEX_CHARS_PER_BAND;
  const bandHex = normalizedHex.slice(
    start,
    start + SIMHASH_CONFIG.HEX_CHARS_PER_BAND,
  );
  return hexToBitString(bandHex);
}

/** Confidence computation matching simhash-match.ts:computeConfidence */
function computeConfidence(
  hammingDistance: number,
  bandMatches: number,
): number {
  const penaltyPerBit = 0.05 / (SIMHASH_CONFIG.TOTAL_BITS / 64);
  const baseConfidence = 0.9 - hammingDistance * penaltyPerBit;
  const bandBonus = Math.min((bandMatches - 2) * 0.02, 0.04);
  return Math.max(0.6, Math.min(0.95, baseConfidence + bandBonus));
}

// ============================================================================
// Read: Unified T1 + T1.5 Match
// ============================================================================

/**
 * Unified query: finds candidates whose stable_hash matches exactly OR
 * whose band hit count meets the minimum threshold.
 *
 * No Hamming distance in SQL — only cheap integer CASE/addition for band
 * hit counting. Hamming distance is computed in application code on the
 * small result set (~10 rows).
 *
 * Parameters:
 *  $1  = stable_hash (TEXT)
 *  $2..$17 = band_0..band_15 (BIT(16))
 *  $18 = MIN_BANDS_MATCH (integer, WHERE filter)
 *  $19 = LIMIT
 */
const UNIFIED_MATCH_SQL = `
  SELECT device_id, stable_hash, fuzzy_hash, last_seen,
         (stable_hash = $1) AS exact_match,
         (CASE WHEN band_0  = $2::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_1  = $3::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_2  = $4::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_3  = $5::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_4  = $6::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_5  = $7::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_6  = $8::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_7  = $9::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_8  = $10::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_9  = $11::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_10 = $12::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_11 = $13::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_12 = $14::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_13 = $15::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_14 = $16::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_15 = $17::BIT(16) THEN 1 ELSE 0 END) AS band_matches
  FROM device_hashes
  WHERE expires_at > NOW()
    AND (
      stable_hash = $1
      OR (CASE WHEN band_0  = $2::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_1  = $3::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_2  = $4::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_3  = $5::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_4  = $6::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_5  = $7::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_6  = $8::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_7  = $9::BIT(16)  THEN 1 ELSE 0 END +
          CASE WHEN band_8  = $10::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_9  = $11::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_10 = $12::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_11 = $13::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_12 = $14::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_13 = $15::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_14 = $16::BIT(16) THEN 1 ELSE 0 END +
          CASE WHEN band_15 = $17::BIT(16) THEN 1 ELSE 0 END) >= $18
    )
  ORDER BY (stable_hash = $1) DESC,
           (CASE WHEN band_0  = $2::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_1  = $3::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_2  = $4::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_3  = $5::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_4  = $6::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_5  = $7::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_6  = $8::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_7  = $9::BIT(16)  THEN 1 ELSE 0 END +
            CASE WHEN band_8  = $10::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_9  = $11::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_10 = $12::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_11 = $13::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_12 = $14::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_13 = $15::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_14 = $16::BIT(16) THEN 1 ELSE 0 END +
            CASE WHEN band_15 = $17::BIT(16) THEN 1 ELSE 0 END) DESC,
           last_seen DESC
  LIMIT $19`;

/** Validate and normalize the fuzzy hash, returning null if invalid. */
function normalizeFuzzyHash(fuzzyHash?: string): string | null {
  if (!fuzzyHash) return null;
  const normalized = fuzzyHash.replace(/^0x/i, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

/** Build query parameters for the unified match SQL. */
function buildMatchParams(
  stableHash: string | null,
  normalizedFuzzy: string | null,
): (string | number | null)[] {
  const bands = normalizedFuzzy
    ? Array.from({ length: 16 }, (_, i) => extractBand(normalizedFuzzy, i))
    : Array.from({ length: 16 }, () => "0".repeat(16));

  return [
    stableHash,
    ...bands,
    SIMHASH_CONFIG.MIN_BANDS_MATCH,
    SIMHASH_CONFIG.MAX_CANDIDATES,
  ];
}

/** Get the last_seen timestamp in epoch seconds from a PG row. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getLastSeenEpoch(row: any): number {
  return row.last_seen instanceof Date
    ? Math.floor(row.last_seen.getTime() / 1000)
    : row.last_seen;
}

/** Check if a candidate passes recency + Hamming thresholds. */
function isValidCandidate(hd: number, lastSeenEpoch: number): boolean {
  if (hd < 0 || hd > SIMHASH_CONFIG.HAMMING_THRESHOLD) return false;
  const ageInDays = (Math.floor(Date.now() / 1000) - lastSeenEpoch) / 86400;
  return !(ageInDays > SIMHASH_CONFIG.RECENCY_WINDOW_DAYS && hd > 1);
}

/** Score SimHash candidates by Hamming distance. Returns best match or null. */
function scoreCandidates(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rows: any[],
  fingerprint: Fingerprint,
): MatchResult | null {
  const incomingHex = fingerprint.fuzzy_hash as string;
  let bestResult: MatchResult | null = null;
  let bestHd = Infinity;

  for (const row of rows) {
    if (row.exact_match || !row.fuzzy_hash) continue;

    const matchedHex = bitStringToHex(row.fuzzy_hash);
    const hd = hammingDistance(incomingHex, matchedHex);
    if (!isValidCandidate(hd, getLastSeenEpoch(row))) continue;

    if (hd < bestHd) {
      bestHd = hd;
      bestResult = buildSimHashMatchResult(
        row,
        fingerprint,
        hd,
        Number(row.band_matches),
      );
    }
  }

  return bestResult;
}

/** Build PgQueryContext from raw query rows and the incoming fuzzy hash. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildPgQueryContext(
  rows: any[],
  incomingHex: string | null,
): PgQueryContext {
  return {
    candidates: rows.map((row) => {
      const candidate: PgQueryContext["candidates"][number] = {
        device_id: row.device_id,
        band_matches: Number(row.band_matches),
        exact_match: Boolean(row.exact_match),
      };
      if (incomingHex && row.fuzzy_hash) {
        const matchedHex = bitStringToHex(row.fuzzy_hash);
        const hd = hammingDistance(incomingHex, matchedHex);
        candidate.hamming_distance = hd;
        candidate.similarity = 1 - hd / SIMHASH_CONFIG.TOTAL_BITS;
      }
      return candidate;
    }),
    total_rows: rows.length,
  };
}

/** Result of pgUnifiedMatch including query context for archiving. */
export interface PgUnifiedMatchResult {
  match: MatchResult | null;
  pgQueryContext: PgQueryContext;
}

/**
 * Unified T1 + T1.5 match against device_hashes.
 *
 * Strategy:
 * 1. SQL returns stable_hash exact matches + SimHash candidates with
 *    band_matches >= MIN_BANDS_MATCH, sorted by band_matches DESC.
 * 2. Application computes Hamming distance on the small result set (~10 rows).
 * 3. Best match wins: stable hash (0.95) > SimHash scored by Hamming distance.
 *
 * Always returns pgQueryContext with candidate details for archive payloads.
 */
const EMPTY_PG_CONTEXT: PgQueryContext = { candidates: [], total_rows: 0 };

function resolveIncomingHex(
  fingerprint: Fingerprint,
  normalizedFuzzy: string | null,
): string | null {
  return (
    normalizedFuzzy ??
    fingerprint.fuzzy_hash?.replace(/^0x/i, "").toLowerCase() ??
    null
  );
}

function pickMatch(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rows: any[],
  fingerprint: Fingerprint,
  normalizedFuzzy: string | null,
): MatchResult | null {
  const stableRow = rows.find((r) => r.exact_match && fingerprint.stable_hash);
  if (stableRow) return buildStableMatchResult(stableRow, fingerprint);
  if (!normalizedFuzzy) return null;
  return scoreCandidates(rows, fingerprint);
}

export async function pgUnifiedMatch(
  pool: Pool,
  fingerprint: Fingerprint,
): Promise<PgUnifiedMatchResult> {
  if (!fingerprint.stable_hash && !fingerprint.fuzzy_hash)
    return { match: null, pgQueryContext: EMPTY_PG_CONTEXT };

  const normalizedFuzzy = normalizeFuzzyHash(fingerprint.fuzzy_hash);
  if (!fingerprint.stable_hash && !normalizedFuzzy)
    return { match: null, pgQueryContext: EMPTY_PG_CONTEXT };

  const params = buildMatchParams(
    fingerprint.stable_hash ?? null,
    normalizedFuzzy,
  );
  const result = await pool.query(UNIFIED_MATCH_SQL, params);
  const pgQueryContext = buildPgQueryContext(
    result.rows,
    resolveIncomingHex(fingerprint, normalizedFuzzy),
  );

  if (result.rows.length === 0) return { match: null, pgQueryContext };

  return {
    match: pickMatch(result.rows, fingerprint, normalizedFuzzy),
    pgQueryContext,
  };
}

function buildStableMatchResult(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  row: any,
  fingerprint: Fingerprint,
): MatchResult {
  const matchedFuzzy = row.fuzzy_hash
    ? bitStringToHex(row.fuzzy_hash)
    : undefined;
  return {
    device_id: row.device_id,
    confidence: 0.95,
    match_tier: MatchTier.HASH,
    is_new_device: false,
    risk_score: 0.3,
    flags: [],
    evidence_codes: ["STABLE_HASH_MATCH"],
    fuzzy_match_info: computeFuzzyMatchInfo(
      fingerprint.fuzzy_hash,
      matchedFuzzy,
    ),
  };
}

function buildSimHashMatchResult(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  row: any,
  fingerprint: Fingerprint,
  hammingDistance: number,
  bandMatches: number,
): MatchResult {
  const matchedHash = bitStringToHex(row.fuzzy_hash);

  return {
    device_id: row.device_id,
    confidence: computeConfidence(hammingDistance, bandMatches),
    match_tier: MatchTier.SIMHASH,
    is_new_device: false,
    risk_score: 0.35,
    flags: [],
    evidence_codes: ["SIMHASH_MATCH"],
    simhash_details: {
      incoming_hash: fingerprint.fuzzy_hash as string,
      matched_hash: matchedHash,
      hamming_distance: hammingDistance,
      similarity: 1 - hammingDistance / SIMHASH_CONFIG.TOTAL_BITS,
      bands_matched: bandMatches,
    },
    fuzzy_match_info: computeFuzzyMatchInfo(
      fingerprint.fuzzy_hash,
      matchedHash,
    ),
  };
}

// ============================================================================
// Write: Unified Device Hash Upsert
// ============================================================================

const DEVICE_HASHES_UPSERT_SQL = `INSERT INTO device_hashes (
    device_id, stable_hash, fuzzy_hash,
    band_0, band_1, band_2, band_3, band_4, band_5, band_6, band_7,
    band_8, band_9, band_10, band_11, band_12, band_13, band_14, band_15,
    last_seen, expires_at
  ) VALUES (
    $1, $2, $3::BIT(256),
    $4::BIT(16), $5::BIT(16), $6::BIT(16), $7::BIT(16),
    $8::BIT(16), $9::BIT(16), $10::BIT(16), $11::BIT(16),
    $12::BIT(16), $13::BIT(16), $14::BIT(16), $15::BIT(16),
    $16::BIT(16), $17::BIT(16), $18::BIT(16), $19::BIT(16),
    to_timestamp($20), to_timestamp($21)
  )
  ON CONFLICT (device_id) DO UPDATE SET
    stable_hash = COALESCE(EXCLUDED.stable_hash, device_hashes.stable_hash),
    fuzzy_hash = COALESCE(EXCLUDED.fuzzy_hash, device_hashes.fuzzy_hash),
    band_0 = COALESCE(EXCLUDED.band_0, device_hashes.band_0),
    band_1 = COALESCE(EXCLUDED.band_1, device_hashes.band_1),
    band_2 = COALESCE(EXCLUDED.band_2, device_hashes.band_2),
    band_3 = COALESCE(EXCLUDED.band_3, device_hashes.band_3),
    band_4 = COALESCE(EXCLUDED.band_4, device_hashes.band_4),
    band_5 = COALESCE(EXCLUDED.band_5, device_hashes.band_5),
    band_6 = COALESCE(EXCLUDED.band_6, device_hashes.band_6),
    band_7 = COALESCE(EXCLUDED.band_7, device_hashes.band_7),
    band_8 = COALESCE(EXCLUDED.band_8, device_hashes.band_8),
    band_9 = COALESCE(EXCLUDED.band_9, device_hashes.band_9),
    band_10 = COALESCE(EXCLUDED.band_10, device_hashes.band_10),
    band_11 = COALESCE(EXCLUDED.band_11, device_hashes.band_11),
    band_12 = COALESCE(EXCLUDED.band_12, device_hashes.band_12),
    band_13 = COALESCE(EXCLUDED.band_13, device_hashes.band_13),
    band_14 = COALESCE(EXCLUDED.band_14, device_hashes.band_14),
    band_15 = COALESCE(EXCLUDED.band_15, device_hashes.band_15),
    last_seen = EXCLUDED.last_seen,
    expires_at = EXCLUDED.expires_at`;

export interface PgDeviceHashesUpsertParams {
  deviceId: string;
  stableHash?: string;
  fuzzyHash?: string;
  lastSeen: number;
  expiresAt: number;
}

/**
 * Upsert a device's hash data (stable + fuzzy + bands) in one write.
 * Uses COALESCE on conflict so a write with only stable_hash won't
 * null out an existing fuzzy_hash (and vice versa).
 */
export async function pgUpsertDeviceHashes(
  pool: Pool,
  params: PgDeviceHashesUpsertParams,
): Promise<void> {
  const { deviceId, stableHash, fuzzyHash, lastSeen, expiresAt } = params;

  let fuzzyBits: string | null = null;
  let bands: (string | null)[] = Array.from({ length: 16 }, () => null);

  if (fuzzyHash) {
    const normalized = fuzzyHash.replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
      logger.warn("pgUpsertDeviceHashes: invalid fuzzy_hash length", {
        length: normalized.length,
      });
    } else {
      fuzzyBits = hexToBitString(normalized);
      bands = Array.from({ length: 16 }, (_, i) => extractBand(normalized, i));
    }
  }

  await pool.query(DEVICE_HASHES_UPSERT_SQL, [
    deviceId,
    stableHash ?? null,
    fuzzyBits,
    ...bands,
    lastSeen,
    expiresAt,
  ]);
}
