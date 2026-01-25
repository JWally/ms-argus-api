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
 * @returns Assembled response data ready for serialization
 *
 * @internal
 */
function buildSessionResponseData(params: {
  sessionId: string;
  rawPayload: SqsPayload;
  matchResult: MatchResult;
  anomalies: SessionAnomalySignal[];
}): Record<string, unknown> {
  const { sessionId, rawPayload, matchResult, anomalies } = params;

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

  return {
    identifiers,
    analysis,
    hashes: rawPayload.hashes,
    device: rawPayload.device,
    sigint: rawPayload.sigint,
  };
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
 * @param deps - AWS and logging dependencies
 * @param deps.dynamodb - DynamoDB client instance
 * @param deps.tableName - Session payload table name
 * @param deps.logger - Logger for warning on failures
 * @param deps.metrics - Metrics for tracking write errors
 *
 * @example
 * ```typescript
 * await writeSessionPayload(
 *   { sessionId, rawPayload, matchResult, anomalies },
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
