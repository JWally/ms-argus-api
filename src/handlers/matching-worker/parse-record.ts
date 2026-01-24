import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { FingerprintPayload } from "../../services/matching";
import { extractFingerprint } from "../../services/matching/fingerprint-extractor";
import { isWarmupMessage } from "../../helpers/is-warmup";
import type { ArgusPayload } from "../../helpers/payload-schema";

// V3 Payload from ingestion handler (ArgusPayload + metadata)
// Supports both V2 "network" and V3 "sigint" field names
export interface SqsPayload extends ArgusPayload {
  _headers?: Record<string, string>;
  _timestamp?: number;
  network?: ArgusPayload["sigint"]; // V2 compat
}

export interface ParsedRecord {
  rawPayload: SqsPayload;
  sessionId: string;
  fingerprint: ReturnType<typeof extractFingerprint>;
  payload: FingerprintPayload;
}

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
