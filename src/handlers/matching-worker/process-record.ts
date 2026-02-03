import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { FirehoseClient } from "@aws-sdk/client-firehose";
import {
  MatchingService,
  generateIdempotencyKey,
  MatchResult,
} from "../../services/matching";
import {
  detectAllAnomalies,
  fetchStatisticalContext,
  fetchNetworkBaselineContext,
  fetchStatisticalContextV2,
  type StatisticalContext,
  type NetworkBaselineDetectorContext,
  type StatisticalContextV2,
} from "../../services/profile/anomaly";
import type { SessionAnomalySignal } from "../../types";
import type { MatchingWorkerEnvConfig } from "../../config/env";
import {
  parseSqsRecord,
  type ParsedRecord,
  type SqsPayload,
} from "./parse-record";
import { recordTierMetric } from "./metrics";
import { emitObservation } from "./observation";
import { writeSessionPayload } from "./session";

/** Dependencies required for processing SQS records in the matching worker. */
export interface ProcessRecordDeps {
  /** Logger instance for structured logging */
  logger: Logger;
  /** Metrics client for CloudWatch metrics */
  metrics: Metrics;
  /** DynamoDB client for session payload persistence */
  dynamodb: DynamoDBClient;
  /** Firehose client for observation streaming */
  firehose: FirehoseClient;
  /** Environment configuration for the matching worker */
  envConfig: MatchingWorkerEnvConfig;
}

/**
 * Execute tiered matching and write degraded result on error.
 *
 * Runs the full matching pipeline through the MatchingService. If matching
 * fails, writes a degraded result to prevent reprocessing and rethrows.
 *
 * @param service - Matching service instance
 * @param params - Session ID, fingerprint, and idempotency key
 * @param deps - Logger and metrics dependencies
 * @returns Match result and tier2 timeout flag
 */
async function runMatching(
  service: MatchingService,
  params: {
    sessionId: string;
    fingerprint: ParsedRecord["fingerprint"];
    idempotencyKey: string;
  },
  deps: { logger: Logger; metrics: Metrics },
): Promise<{ matchResult: MatchResult; tier2TimedOut: boolean }> {
  const { sessionId, fingerprint, idempotencyKey } = params;
  try {
    const response = await service.runTieredMatching(fingerprint);
    recordTierMetric(
      response.result.match_tier,
      response.result.is_new_device,
      deps.metrics,
    );
    if (response.tier2TimedOut) {
      deps.metrics.addMetric("Tier2Timeout", MetricUnit.Count, 1);
      deps.logger.warn("Tier2 matching timed out", { session_id: sessionId });
    }
    return {
      matchResult: response.result,
      tier2TimedOut: response.tier2TimedOut,
    };
  } catch (error) {
    deps.logger.error("Matching failed", { error, session_id: sessionId });
    const written = await service.writeDegradedResult(
      sessionId,
      idempotencyKey,
    );
    if (!written) {
      deps.metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
    }
    throw error;
  }
}

/**
 * Extract anomaly signals from fingerprint and device data.
 *
 * Runs all anomaly detectors and transforms results into session signals.
 *
 * @param fingerprint - Normalized fingerprint data
 * @param rawPayload - Raw SQS payload containing device info
 * @param statisticalContext - Pre-fetched statistical context for frequency-based detection
 * @param networkBaselineContext - Pre-fetched network baseline context for ASN-based detection
 * @param statisticalContextV2 - Pre-fetched statistical v2 context for Shannon scoring
 * @returns Array of anomaly signals for the session
 */
function buildAnomalySignals(
  fingerprint: ParsedRecord["fingerprint"],
  rawPayload: SqsPayload,
  statisticalContext: StatisticalContext | null,
  networkBaselineContext: NetworkBaselineDetectorContext | null,
  statisticalContextV2: StatisticalContextV2 | null,
): SessionAnomalySignal[] {
  const result = detectAllAnomalies(
    fingerprint,
    rawPayload.device,
    undefined,
    statisticalContext,
    networkBaselineContext,
    statisticalContextV2,
  );
  return result.signals.map((s) => ({
    type: s.type,
    code: s.code,
    severity: s.severity,
    evidence: s.evidence,
  }));
}

/**
 * Persist matching results to cache, session table, and profile queue.
 *
 * Writes the match result to session cache, stores the full session payload
 * in DynamoDB, and queues a profile update message for the matched device.
 *
 * @param service - Matching service instance
 * @param ctx - Session context with match result and anomalies
 * @param deps - Handler dependencies
 */
async function persistResults(
  service: MatchingService,
  ctx: {
    sessionId: string;
    matchResult: MatchResult;
    idempotencyKey: string;
    anomalies: SessionAnomalySignal[];
    rawPayload: SqsPayload;
    payload: ParsedRecord["payload"];
    statisticalContext: StatisticalContext | null;
    statisticalContextV2: StatisticalContextV2 | null;
  },
  deps: ProcessRecordDeps,
): Promise<void> {
  const {
    sessionId,
    matchResult,
    idempotencyKey,
    anomalies,
    rawPayload,
    payload,
    statisticalContext,
    statisticalContextV2,
  } = ctx;
  const cacheWritten = await service.writeMatchResult({
    sessionId,
    result: matchResult,
    idempotencyKey,
    anomalies,
  });
  if (!cacheWritten) {
    deps.metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
  }
  await writeSessionPayload(
    {
      sessionId,
      rawPayload,
      matchResult,
      anomalies,
      statisticalContext,
      statisticalContextV2,
    },
    {
      dynamodb: deps.dynamodb,
      tableName: deps.envConfig.SESSION_PAYLOAD_TABLE,
      logger: deps.logger,
      metrics: deps.metrics,
    },
  );
  await service.queueProfileUpdate(
    matchResult.device_id,
    payload,
    matchResult.is_new_device,
    matchResult,
  );
}

/**
 * Log duration metrics and emit observation record.
 *
 * Records matching duration to CloudWatch and sends an observation
 * record to Firehose for analytics. Observation emission is fire-and-forget.
 *
 * @param params - Session ID, match result, timeout flag, and duration
 * @param deps - Handler dependencies
 */
function emitCompletionMetrics(
  params: {
    sessionId: string;
    matchResult: MatchResult;
    tier2TimedOut: boolean;
    duration: number;
  },
  deps: ProcessRecordDeps,
): void {
  deps.metrics.addMetric(
    "MatchingDuration",
    MetricUnit.Milliseconds,
    params.duration,
  );
  emitObservation(
    {
      sessionId: params.sessionId,
      matchResult: params.matchResult,
      tier2TimedOut: params.tier2TimedOut,
      durationMs: params.duration,
    },
    {
      firehose: deps.firehose,
      streamName: deps.envConfig.OBSERVATIONS_STREAM_NAME,
      logger: deps.logger,
      metrics: deps.metrics,
    },
  ).catch(() => {
    /* logged in emitObservation */
  });
  deps.logger.info("Matching complete", {
    session_id: params.sessionId,
    device_id: params.matchResult.device_id,
    duration: params.duration,
    tier: params.matchResult.match_tier,
  });
}

/**
 * Process a single SQS record through the matching pipeline.
 *
 * Main entry point for the matching worker. Parses the record, checks cache
 * for duplicates, runs tiered matching, detects anomalies, persists results,
 * upserts device vector (if configured), and emits metrics.
 * Short-circuits on cache hit or parse failure.
 *
 * @param record - SQS record containing fingerprint payload
 * @param service - Matching service instance
 * @param deps - Handler dependencies
 */
export async function processRecord(
  record: SQSRecord,
  service: MatchingService,
  deps: ProcessRecordDeps,
): Promise<void> {
  const parsed = parseSqsRecord(record, deps);
  if (!parsed) return;

  const startTime = Date.now();
  const { rawPayload, sessionId, fingerprint, payload } = parsed;

  deps.logger.info("Processing fingerprint", { session_id: sessionId });
  const idempotencyKey = generateIdempotencyKey(sessionId, fingerprint);

  const cached = await service.cache.checkSessionCache(sessionId);
  if (cached && cached.status === "complete") {
    deps.logger.info("Cache hit - already processed", {
      session_id: sessionId,
      device_id: cached.device_id,
    });
    deps.metrics.addMetric("Tier0CacheHit", MetricUnit.Count, 1);
    return;
  }

  const { matchResult, tier2TimedOut } = await runMatching(
    service,
    { sessionId, fingerprint, idempotencyKey },
    deps,
  );

  // Fetch statistical and network baseline contexts in parallel
  // These are non-blocking on failure - detectors return empty signals if context is null
  const [statisticalContext, networkBaselineContext, statisticalContextV2] =
    await Promise.all([
      fetchStatisticalContext(fingerprint),
      fetchNetworkBaselineContext(fingerprint, rawPayload.sigint),
      fetchStatisticalContextV2(
        fingerprint,
        rawPayload.sigint,
        rawPayload.device,
      ),
    ]);

  const anomalies = buildAnomalySignals(
    fingerprint,
    rawPayload,
    statisticalContext,
    networkBaselineContext,
    statisticalContextV2,
  );
  await persistResults(
    service,
    {
      sessionId,
      matchResult,
      idempotencyKey,
      anomalies,
      rawPayload,
      payload,
      statisticalContext,
      statisticalContextV2,
    },
    deps,
  );

  // Upsert device vector to Qdrant (fire-and-forget, non-blocking)
  // This keeps the vector database in sync with the device profile
  service.upsertVector(matchResult.device_id, fingerprint).catch((error) => {
    deps.logger.warn("Vector upsert failed", {
      error,
      device_id: matchResult.device_id,
    });
  });

  const duration = Date.now() - startTime;
  emitCompletionMetrics(
    { sessionId, matchResult, tier2TimedOut, duration },
    deps,
  );
}
