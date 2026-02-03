/**
 * @fileoverview Session payload persistence for the matching worker.
 * Writes full session response data to DynamoDB for later retrieval by session-get.
 * @module handlers/matching-worker/session
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { gzipSync } from "zlib";
import type { MatchResult } from "../../services/matching";
import { SESSION_PAYLOAD_TTL_SECONDS } from "../../helpers/constants";
import type { SessionAnomalySignal } from "../../types";
import type { SqsPayload } from "./parse-record";
import type {
  StatisticalContext,
  StatisticalContextV2,
} from "../../services/profile/anomaly";

/**
 * Constructs the full session response data object for storage.
 *
 * Combines identifiers, analysis results, hashes, device info, and sigint
 * into the canonical SessionResponse format. Optional fields like anomalies
 * and simhash_details are only included when present.
 *
 * @param params - Components to assemble into the response
 * @param params.sessionId - Session identifier
 * @param params.rawPayload - Original ingested payload with device data
 * @param params.matchResult - Results from the matching service
 * @param params.anomalies - Detected anomaly signals (empty array if none)
 * @param params.statisticalContext - V1 statistical context (JA4/UA frequency)
 * @param params.statisticalContextV2 - V2 statistical context (Shannon scoring)
 * @returns Assembled response data ready for serialization
 *
 * @internal
 */
function buildSessionResponseData(params: {
  sessionId: string;
  rawPayload: SqsPayload;
  matchResult: MatchResult;
  anomalies: SessionAnomalySignal[];
  statisticalContext?: StatisticalContext | null;
  statisticalContextV2?: StatisticalContextV2 | null;
}): Record<string, unknown> {
  const {
    sessionId,
    rawPayload,
    matchResult,
    anomalies,
    statisticalContext: _statisticalContext, // V1 deprecated, kept for API compatibility
    statisticalContextV2,
  } = params;

  const identifiers: Record<string, unknown> = {
    session_id: sessionId,
    device_id: matchResult.device_id,
  };
  if (rawPayload.identifiers.evercookie_id) {
    identifiers.evercookie_id = rawPayload.identifiers.evercookie_id;
  }
  if (rawPayload.identifiers.public_key) {
    identifiers.public_key = rawPayload.identifiers.public_key;
  }

  const analysis: Record<string, unknown> = {
    status: "complete",
    confidence: matchResult.confidence,
    match_tier: matchResult.match_tier,
    is_new_device: matchResult.is_new_device,
    risk_score: matchResult.risk_score,
    flags: matchResult.flags,
    evidence_codes: matchResult.evidence_codes,
  };
  if (anomalies.length > 0) {
    analysis.anomalies = anomalies;
  }
  if (matchResult.simhash_details) {
    analysis.simhash_details = matchResult.simhash_details;
  }
  if (matchResult.fuzzy_match_info) {
    analysis.fuzzy_match_info = matchResult.fuzzy_match_info;
  }
  if (matchResult.vector_match_details) {
    analysis.vector_match_details = matchResult.vector_match_details;
  }

  // Build fingerprint analysis object with Redis-based statistical data (V2 only)
  if (statisticalContextV2) {
    const fingerprints: Record<string, unknown> = {};

    // Add scores for each fingerprint type
    for (const [type, score] of Object.entries(statisticalContextV2.scores)) {
      if (score) {
        fingerprints[type] = {
          value: statisticalContextV2.fingerprints[type],
          grouped_by: score.groupingKey,
          score: score.score,
          confidence: score.confidence,
          raw_ua_score: score.rawUaScore,
          raw_global_score: score.rawGlobalScore,
          ua_total: score.uaTotal,
          global_total: score.globalTotal,
        };
      }
    }

    const fingerprintAnalysis: Record<string, unknown> = {
      user_agent_family: statisticalContextV2.uaFamily,
      fingerprints,
    };

    if (statisticalContextV2.combinedScore !== null) {
      fingerprintAnalysis.combined_score = statisticalContextV2.combinedScore;
    }
    if (statisticalContextV2.baselineSkipped !== undefined) {
      fingerprintAnalysis.baseline_skipped =
        statisticalContextV2.baselineSkipped;
    }
    if (
      statisticalContextV2.matchedRules &&
      statisticalContextV2.matchedRules.length > 0
    ) {
      fingerprintAnalysis.matched_rules = statisticalContextV2.matchedRules;
    }

    analysis.fingerprint_analysis = fingerprintAnalysis;
  }

  const result: Record<string, unknown> = {
    identifiers,
    analysis,
    hashes: rawPayload.hashes,
    device: rawPayload.device,
    sigint: rawPayload.sigint,
  };

  return result;
}

/**
 * Writes the full session payload to DynamoDB for later retrieval.
 *
 * The payload is gzip-compressed and base64-encoded to reduce storage costs.
 * A TTL is set based on SESSION_PAYLOAD_TTL_SECONDS for automatic cleanup.
 *
 * Write failures are logged but do not throw - session cache still contains
 * the essential matching result, so degraded mode retrieval remains possible.
 *
 * @param params - Session data to persist
 * @param params.sessionId - Session identifier (becomes partition key)
 * @param params.rawPayload - Original payload with device/sigint data
 * @param params.matchResult - Matching service results
 * @param params.anomalies - Detected anomaly signals
 * @param params.statisticalContext - V1 statistical context (JA4/UA frequency)
 * @param params.statisticalContextV2 - V2 statistical context (Shannon scoring)
 * @param deps - AWS and logging dependencies
 * @param deps.dynamodb - DynamoDB client instance
 * @param deps.tableName - Session payload table name
 * @param deps.logger - Logger for warning on failures
 * @param deps.metrics - Metrics for tracking write errors
 *
 * @example
 * ```typescript
 * await writeSessionPayload(
 *   { sessionId, rawPayload, matchResult, anomalies, statisticalContext, statisticalContextV2 },
 *   { dynamodb, tableName: "session-payloads", logger, metrics }
 * );
 * ```
 */
export async function writeSessionPayload(
  params: {
    sessionId: string;
    rawPayload: SqsPayload;
    matchResult: MatchResult;
    anomalies: SessionAnomalySignal[];
    statisticalContext?: StatisticalContext | null;
    statisticalContextV2?: StatisticalContextV2 | null;
  },
  deps: {
    dynamodb: DynamoDBClient;
    tableName: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<void> {
  const { sessionId } = params;
  const ttl = Math.floor(Date.now() / 1000) + SESSION_PAYLOAD_TTL_SECONDS;

  try {
    const fullData = buildSessionResponseData(params);
    const gzipped = gzipSync(Buffer.from(JSON.stringify(fullData)));
    const payloadGzipB64 = gzipped.toString("base64");

    await deps.dynamodb.send(
      new PutItemCommand({
        TableName: deps.tableName,
        Item: {
          session_id: { S: sessionId },
          payload_gzip_b64: { S: payloadGzipB64 },
          ttl: { N: String(ttl) },
          created_at: { S: new Date().toISOString() },
        },
      }),
    );
  } catch (error) {
    deps.logger.warn("Failed to write session payload", { error, sessionId });
    deps.metrics.addMetric("SessionPayloadWriteError", MetricUnit.Count, 1);
  }
}
