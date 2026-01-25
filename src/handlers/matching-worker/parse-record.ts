/**
 * @fileoverview SQS record parsing utilities for the matching worker.
 * Handles deserialization, validation, and normalization of fingerprint payloads
 * received from the ingestion queue.
 * @module handlers/matching-worker/parse-record
 */

import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { FingerprintPayload } from "../../services/matching";
import { extractFingerprint } from "../../services/matching/fingerprint-extractor";
import { isWarmupMessage } from "../../helpers/is-warmup";
import type { ArgusPayload } from "../../helpers/payload-schema";

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
export function parseSqsRecord(
  record: SQSRecord,
  deps: { logger: Logger; metrics: Metrics },
): ParsedRecord | null {
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
