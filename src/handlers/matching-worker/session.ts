import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { gzipSync } from "zlib";
import type { MatchResult } from "../../services/matching";
import { SESSION_PAYLOAD_TTL_SECONDS } from "../../helpers/constants";
import type { SessionAnomalySignal } from "../../types";
import type { SqsPayload } from "./parse-record";

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
