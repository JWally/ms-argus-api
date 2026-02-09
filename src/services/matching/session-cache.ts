import { DynamoCacheService } from "../cache";
import { MatchResult, SessionCacheValue, SessionAnomalySignal } from "./types";

export interface SessionCacheDeps {
  cache: DynamoCacheService;
}

export interface WriteMatchResultParams {
  sessionId: string;
  result: MatchResult;
  idempotencyKey: string;
  anomalies?: SessionAnomalySignal[];
}

/** Conditional write — only updates if confidence is higher than existing. */
export async function writeMatchResult(
  deps: SessionCacheDeps,
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

    fuzzy_match_info: result.fuzzy_match_info,
    vector_match_details: result.vector_match_details,
    updated_at: Date.now(),
  };

  return deps.cache.writeSessionCache(sessionId, value);
}

/** Write degraded placeholder to prevent reprocessing after failure. */
export async function writeDegradedResult(
  deps: SessionCacheDeps,
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
