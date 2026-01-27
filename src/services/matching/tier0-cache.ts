/**
 * Tier 0 session cache operations.
 *
 * Provides fast session-level caching to deduplicate requests and serve
 * cached results for already-processed sessions.
 * @module
 */
import { DynamoCacheService } from "../cache";
import { MatchResult, SessionCacheValue, SessionAnomalySignal } from "./types";

/** Dependencies for tier-0 cache operations. */
export interface Tier0CacheDeps {
  /** DynamoDB cache service instance */
  cache: DynamoCacheService;
}

/** Parameters for writing a match result to cache. */
export interface WriteMatchResultParams {
  sessionId: string;
  result: MatchResult;
  idempotencyKey: string;
  anomalies?: SessionAnomalySignal[];
}

/**
 * Write match result to session cache.
 *
 * Stores the complete match result including device ID, confidence,
 * and anomalies. Uses conditional write to only update if confidence
 * is higher than any existing cached value.
 *
 * @param deps - Cache service dependency
 * @param params - Session ID, match result, idempotency key, and anomalies
 * @returns True if written, false if skipped due to higher existing confidence
 */
export async function writeMatchResult(
  deps: Tier0CacheDeps,
  params: WriteMatchResultParams,
): Promise<boolean> {
  const { sessionId, result, idempotencyKey, anomalies } = params;
  const value: SessionCacheValue = {
    status: "complete",
    device_id: result.device_id,
    risk_score: result.risk_score,
    confidence: result.confidence,
    match_tier: result.match_tier,
    match_version: Date.now(),
    idempotency_key: idempotencyKey,
    flags: result.flags,
    evidence_codes: result.evidence_codes,
    anomalies: anomalies?.length ? anomalies : undefined,
    simhash_details: result.simhash_details,
    fuzzy_match_info: result.fuzzy_match_info,
    vector_match_details: result.vector_match_details,
    updated_at: Date.now(),
  };

  // DynamoCacheService handles conditional write (only updates if confidence is higher)
  return deps.cache.writeSessionCache(sessionId, value);
}

/**
 * Write degraded status to cache when matching fails.
 *
 * Records a placeholder result indicating matching failed. This prevents
 * the session from being reprocessed and returns a degraded response
 * to callers. Uses conditional write to avoid overwriting valid results.
 *
 * @param deps - Cache service dependency
 * @param sessionId - Session ID to mark as degraded
 * @param idempotencyKey - Idempotency key for the request
 * @returns True if written, false if skipped due to existing valid result
 */
export async function writeDegradedResult(
  deps: Tier0CacheDeps,
  sessionId: string,
  idempotencyKey: string,
): Promise<boolean> {
  const value: SessionCacheValue = {
    status: "degraded",
    device_id: "",
    risk_score: 0.5,
    confidence: 0,
    match_tier: -1,
    match_version: Date.now(),
    idempotency_key: idempotencyKey,
    flags: ["matching_failed"],
    evidence_codes: [],
    updated_at: Date.now(),
  };

  return deps.cache.writeSessionCache(sessionId, value);
}
