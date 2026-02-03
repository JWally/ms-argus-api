/**
 * @fileoverview Observation emission for the matching worker.
 * Sends matching telemetry to Kinesis Firehose for analytics and ML training.
 * @module handlers/matching-worker/observation
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import type { MatchResult } from "../../services/matching";

/**
 * Observation record structure matching Glue table schema.
 * Used for Firehose -> S3 -> Athena analytics pipeline.
 */
export interface ObservationRecord {
  timestamp: number;
  session_id: string;
  tenant_id: string;
  device_id: string;
  match_tier: number;
  confidence: number;
  is_new_device: boolean;
  risk_score: number;
  evidence_codes: string[];
  tier2_timed_out: boolean;
  processing_duration_ms: number;
}

/**
 * Emits a matching observation record to Kinesis Firehose for analytics.
 *
 * Observations are used for:
 * - Matching accuracy analysis and ML model training
 * - Latency monitoring and SLA tracking
 * - New device rate monitoring
 * - Tier distribution analytics
 *
 * Failures are logged but do not throw - this is a non-critical side effect.
 *
 * @param params - Observation data to emit
 * @param params.sessionId - Session identifier for the match attempt
 * @param params.matchResult - Result from the matching service
 * @param params.tier2TimedOut - Whether tier2 matching exceeded its timeout
 * @param params.durationMs - Total matching duration in milliseconds
 * @param deps - AWS and logging dependencies
 * @param deps.firehose - Kinesis Firehose client instance
 * @param deps.streamName - Firehose delivery stream name (undefined disables emission)
 * @param deps.logger - Logger for warning on failures
 * @param deps.metrics - Metrics for tracking emission errors
 *
 * @example
 * ```typescript
 * await emitObservation(
 *   { sessionId, matchResult, tier2TimedOut: false, durationMs: 45 },
 *   { firehose, streamName: "argus-observations", logger, metrics }
 * );
 * ```
 */
export async function emitObservation(
  params: {
    sessionId: string;
    matchResult: MatchResult;
    tier2TimedOut: boolean;
    durationMs: number;
  },
  deps: {
    firehose: FirehoseClient;
    streamName: string | undefined;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<void> {
  if (!deps.streamName) {
    return;
  }

  const observation: ObservationRecord = {
    timestamp: Date.now(),
    session_id: params.sessionId,
    tenant_id: "", // Deprecated field, kept for schema compatibility
    device_id: params.matchResult.device_id,
    match_tier: params.matchResult.match_tier,
    confidence: params.matchResult.confidence,
    is_new_device: params.matchResult.is_new_device,
    risk_score: params.matchResult.risk_score,
    evidence_codes: params.matchResult.evidence_codes,
    tier2_timed_out: params.tier2TimedOut,
    processing_duration_ms: params.durationMs,
  };

  try {
    await deps.firehose.send(
      new PutRecordCommand({
        DeliveryStreamName: deps.streamName,
        Record: {
          Data: Buffer.from(JSON.stringify(observation) + "\n"),
        },
      }),
    );
  } catch (error) {
    deps.logger.warn("Failed to emit observation to Firehose", {
      error,
      sessionId: params.sessionId,
    });
    deps.metrics.addMetric("ObservationEmitError", MetricUnit.Count, 1);
  }
}
