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
import { resolveBrowserIdentity } from "../../helpers/browser-identity";

function buildIdentifiers(
  sessionId: string,
  rawPayload: SqsPayload,
  matchResult: MatchResult,
): Record<string, unknown> {
  const identifiers: Record<string, unknown> = {
    session_id: sessionId,
    device_id: matchResult.device_id,
  };
  if (rawPayload.identifiers.evercookie_id)
    identifiers.evercookie_id = rawPayload.identifiers.evercookie_id;
  if (rawPayload.identifiers.public_key)
    identifiers.public_key = rawPayload.identifiers.public_key;
  return identifiers;
}

function buildBrowserAnomalies(
  device: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lies = device.lies as Record<string, unknown> | undefined;
  const headless = device.headless as Record<string, unknown> | undefined;
  const capturedErrors = device.capturedErrors as
    | Record<string, unknown>
    | undefined;

  if (lies && (lies.totalLies as number) > 0) {
    result.lies = { total: lies.totalLies, data: lies.data };
  }
  if (headless) {
    const lhr = headless.likeHeadlessRating as number;
    const hr = headless.headlessRating as number;
    const sr = headless.stealthRating as number;
    if (lhr > 0 || hr > 0 || sr > 0) {
      result.headless = {
        likeHeadlessRating: lhr,
        headlessRating: hr,
        stealthRating: sr,
        likeHeadless: headless.likeHeadless,
        headless: headless.headless,
        stealth: headless.stealth,
      };
    }
  }
  if (capturedErrors) {
    const errorData = capturedErrors.data as unknown[];
    if (Array.isArray(errorData) && errorData.length > 0)
      result.errors = errorData;
  }
  return result;
}

function buildAnalysis(opts: {
  matchResult: MatchResult;
  anomalies: SessionAnomalySignal[];
  device: Record<string, unknown>;
  sigint?: Record<string, unknown>;
}): Record<string, unknown> {
  const { matchResult, anomalies, device, sigint } = opts;
  const analysis: Record<string, unknown> = {
    status: "complete",
    confidence: matchResult.confidence,
    match_tier: matchResult.match_tier,
    is_new_device: matchResult.is_new_device,
    risk_score: matchResult.risk_score,
    flags: matchResult.flags,
    evidence_codes: matchResult.evidence_codes,
    browser: resolveBrowserIdentity(device, sigint),
  };
  const browserAnomalies = buildBrowserAnomalies(device);
  if (Object.keys(browserAnomalies).length > 0)
    analysis.anomalies = browserAnomalies;
  if (anomalies.length > 0) analysis.suspicious = anomalies;

  if (matchResult.fuzzy_match_info)
    analysis.fuzzy_match_info = matchResult.fuzzy_match_info;
  if (matchResult.vector_match_details)
    analysis.vector_match_details = matchResult.vector_match_details;
  if (matchResult.ip_history_context)
    analysis.ip_history_context = matchResult.ip_history_context;

  return analysis;
}

export function buildSessionResponseData(params: {
  sessionId: string;
  rawPayload: SqsPayload;
  matchResult: MatchResult;
  anomalies: SessionAnomalySignal[];
}): Record<string, unknown> {
  const { sessionId, rawPayload, matchResult, anomalies } = params;
  return {
    identifiers: buildIdentifiers(sessionId, rawPayload, matchResult),
    analysis: buildAnalysis({
      matchResult,
      anomalies,
      device: rawPayload.device || {},
      sigint: rawPayload.sigint as Record<string, unknown> | undefined,
    }),
    hashes: rawPayload.hashes,
    device: rawPayload.device,
    sigint: rawPayload.sigint,
  };
}

/** Write gzip-compressed session payload to DynamoDB. Failures are logged, not thrown. */
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
