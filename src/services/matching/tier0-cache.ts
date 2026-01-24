// src/services/matching/tier0-cache.ts
// AR-119: Extracted from matching-service.ts - Session cache operations (Tier 0)
// AR-148: Added anomalies parameter to writeMatchResult
import { DynamoCacheService } from "../cache";
import { MatchResult, SessionCacheValue, SessionAnomalySignal } from "./types";

/**
 * Dependencies for tier 0 cache operations
 */
export interface Tier0CacheDeps {
  cache: DynamoCacheService;
}

/**
 * Check if session is already cached (AR-52: DynamoDB replaces Redis)
 */
export function checkCache(
  deps: Tier0CacheDeps,
  sessionId: string,
): Promise<SessionCacheValue | null> {
  return deps.cache.checkSessionCache(sessionId);
}

/**
 * Write match result to session cache (AR-52: DynamoDB replaces Redis)
 * AR-148: Added optional anomalies parameter for server-side detection results
 * AR-170: Returns boolean indicating if write succeeded or was skipped
 *
 * @returns true if written, false if skipped (existing value has higher confidence)
 */
export async function writeMatchResult(
  deps: Tier0CacheDeps,
  sessionId: string,
  result: MatchResult,
  idempotencyKey: string,
  anomalies?: SessionAnomalySignal[],
): Promise<boolean> {
  const value: SessionCacheValue = {
    status: "complete",
    device_id: result.device_id,
    risk_score: result.risk_score,
    confidence: result.confidence,
    match_tier: result.match_tier,
    match_version: Date.now(),
    idempotency_key: idempotencyKey,
    flags: result.flags,
    evidence_codes: result.evidence_codes, // AR-54
    anomalies: anomalies?.length ? anomalies : undefined, // AR-148: Only include if signals detected
    simhash_details: result.simhash_details, // AR-XXX: Include SimHash match details
    fuzzy_match_info: result.fuzzy_match_info, // AR-XXX: Include fuzzy hash drift info
    updated_at: Date.now(),
  };

  // DynamoCacheService handles conditional write (only updates if confidence is higher)
  return deps.cache.writeSessionCache(sessionId, value);
}

/**
 * Write degraded status to cache when matching fails (AR-52: DynamoDB replaces Redis)
 * AR-170: Returns boolean indicating if write succeeded or was skipped
 *
 * @returns true if written, false if skipped (existing value has higher confidence)
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
    evidence_codes: [], // AR-54: No evidence when matching fails
    updated_at: Date.now(),
  };

  return deps.cache.writeSessionCache(sessionId, value);
}
