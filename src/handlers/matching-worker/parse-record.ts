/**
 * @fileoverview SQS record parsing utilities for the matching worker.
 * Handles deserialization, validation, and normalization of fingerprint payloads
 * received from the ingestion queue.
 * @module handlers/matching-worker/parse-record
 */

import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { FingerprintPayload } from "../../services/matching";
import { extractFingerprint } from "../../services/matching/fingerprint-extractor";
import { isWarmupMessage } from "../../helpers/is-warmup";
import type { ArgusPayload } from "../../helpers/payload-schema";
import {
  isEncryptedResponse,
  decryptProbeResponse,
} from "../../helpers/decrypt-probe";
import {
  redeemSigintTokens,
  extractInlineToken,
} from "../../helpers/redeem-sigint-tokens";

/**
 * Extended payload structure received from the ingestion handler via SQS.
 * Extends the base ArgusPayload with internal metadata fields and provides
 * backward compatibility for V2 "network" field naming.
 *
 * @interface SqsPayload
 * @extends ArgusPayload
 */
export interface SqsPayload extends ArgusPayload {
  /** HTTP headers from the original request, prefixed with underscore to indicate internal metadata */
  _headers?: Record<string, string>;
  /** Unix timestamp (ms) when the payload was ingested */
  _timestamp?: number;
  /** V2 compatibility: maps to V3 "sigint" field for older clients */
  network?: ArgusPayload["sigint"];
}

/**
 * Successfully parsed and normalized SQS record ready for matching.
 *
 * @interface ParsedRecord
 */
export interface ParsedRecord {
  /** Original payload with V2→V3 normalization applied */
  rawPayload: SqsPayload;
  /** Unique session identifier extracted from identifiers.session_id */
  sessionId: string;
  /** Extracted fingerprint signals for device matching */
  fingerprint: ReturnType<typeof extractFingerprint>;
  /** Normalized payload structure for the matching service */
  payload: FingerprintPayload;
}

/**
 * Rename legacy client-sent sigint field names to current names.
 * ms-argus-web still sends tlsFingerprint/tcpProbe/h2Probe/stun — normalise
 * them before token redemption so all downstream code uses the new names.
 */
function normalizeSigintFieldNames(payload: SqsPayload): void {
  if (!payload.sigint) return;
  const s = payload.sigint as Record<string, unknown>;
  if (!s.aws_cf && s.tlsFingerprint !== undefined) {
    s.aws_cf = s.tlsFingerprint;
    delete s.tlsFingerprint;
  }
  if (!s.tcp_probe && s.tcpProbe !== undefined) {
    s.tcp_probe = s.tcpProbe;
    delete s.tcpProbe;
  }
  if (!s.h2 && s.h2Probe !== undefined) {
    s.h2 = s.h2Probe;
    delete s.h2Probe;
  }
  delete s.stun;
}

/** Apply sigintTls JSON string to sigint.aws_cf in-place. No key or DynamoDB needed. */
function applyTlsJson(payload: SqsPayload): void {
  if (!payload.sigintTls) return;
  if (!payload.sigint) payload.sigint = {};
  if (payload.sigint.aws_cf) return;
  try {
    payload.sigint.aws_cf = JSON.parse(payload.sigintTls);
  } catch {
    // ignore malformed TLS JSON
  }
}

/**
 * Redeem sigint tokens (TCP/H2/TLS) in-place when SIGINT_AES_KEY and
 * PROBE_TOKENS_TABLE_NAME are set. Runs before fingerprint extraction so that
 * JA3/JA4/RTT signals are available to the matching pipeline.
 */
async function enrichSigintFromTokens(
  payload: SqsPayload,
  dynamodb: DynamoDBClient,
  logger: Logger,
): Promise<void> {
  applyTlsJson(payload);

  const key = process.env.SIGINT_AES_KEY;
  const tableName = process.env.PROBE_TOKENS_TABLE_NAME;
  if (!key || !tableName) return;
  const hasInlineTcpToken = !!extractInlineToken(payload.sigint?.tcp_probe);
  const hasInlineH2Token = !!extractInlineToken(payload.sigint?.h2);
  if (
    !payload.sigintTcpToken &&
    !payload.sigintH2Token &&
    !payload.sigintTls &&
    !hasInlineTcpToken &&
    !hasInlineH2Token
  )
    return;

  try {
    const enriched = await redeemSigintTokens(
      payload,
      key,
      tableName,
      dynamodb,
    );
    payload.sigint = enriched.sigint;
  } catch (err) {
    logger.warn(
      "Failed to redeem sigint tokens — continuing without enrichment",
      {
        error: err,
        session_id: payload.identifiers?.session_id,
      },
    );
  }
}

/** Decrypt sigint probe blobs in-place when SIGINT_AES_KEY is set. */
function decryptSigintProbes(payload: SqsPayload, logger: Logger): void {
  const key = process.env.SIGINT_AES_KEY;
  if (!payload.sigint || !key) return;
  try {
    if (isEncryptedResponse(payload.sigint.tcp_probe)) {
      payload.sigint.tcp_probe = decryptProbeResponse(
        payload.sigint.tcp_probe,
        key,
      );
    }
    if (isEncryptedResponse(payload.sigint.h2)) {
      payload.sigint.h2 = decryptProbeResponse(payload.sigint.h2, key);
    }
  } catch (err) {
    logger.warn(
      "Failed to decrypt sigint probe data — continuing with encrypted blob",
      {
        error: err,
        session_id: payload.identifiers?.session_id,
      },
    );
  }
}

/**
 * Parses and validates an SQS record containing a fingerprint payload.
 *
 * Performs the following operations:
 * 1. Detects and handles warmup messages (returns null)
 * 2. Parses JSON body with error handling
 * 3. Normalizes V2 "network" field to V3 "sigint"
 * 4. Validates required session_id presence
 * 5. Extracts fingerprint signals for matching
 *
 * @param record - Raw SQS record from the Lambda event
 * @param deps - Dependencies for logging and metrics
 * @param deps.logger - Logger instance for debug/error output
 * @param deps.metrics - Metrics instance for CloudWatch metrics
 * @returns Parsed record ready for matching, or null if the record should be skipped
 *          (warmup message, malformed JSON, or missing session_id)
 *
 * @example
 * ```typescript
 * const parsed = parseSqsRecord(record, { logger, metrics });
 * if (parsed) {
 *   await matchingService.match(parsed.payload);
 * }
 * ```
 */
export async function parseSqsRecord(
  record: SQSRecord,
  deps: { logger: Logger; metrics: Metrics; dynamodb: DynamoDBClient },
): Promise<ParsedRecord | null> {
  const { logger, metrics } = deps;

  if (isWarmupMessage(record.body)) {
    logger.info("Warmup ping received - keeping pipeline warm");
    metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return null;
  }

  let rawPayload: SqsPayload;
  try {
    rawPayload = JSON.parse(record.body);
  } catch (parseError) {
    logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200),
    });
    metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return null;
  }

  // Normalize V2 "network" → V3 "sigint"
  if (!rawPayload.sigint && rawPayload.network) {
    rawPayload.sigint = rawPayload.network;
  }

  normalizeSigintFieldNames(rawPayload);
  decryptSigintProbes(rawPayload, logger);
  await enrichSigintFromTokens(rawPayload, deps.dynamodb, logger);

  const sessionId = rawPayload.identifiers?.session_id;
  if (!sessionId) {
    logger.error("Missing session_id in payload", {
      messageId: record.messageId,
    });
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    return null;
  }

  const fingerprint = extractFingerprint(rawPayload, rawPayload._headers);
  const payload: FingerprintPayload = {
    session_id: sessionId,
    fingerprint,
    sigint: rawPayload.sigint as FingerprintPayload["sigint"],
    headers: rawPayload._headers || {},
    timestamp: rawPayload._timestamp || Date.now(),
  };

  return { rawPayload, sessionId, fingerprint, payload };
}
