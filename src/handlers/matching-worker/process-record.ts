import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { FirehoseClient } from "@aws-sdk/client-firehose";
import { S3Client } from "@aws-sdk/client-s3";
import {
  MatchingService,
  generateIdempotencyKey,
  MatchResult,
} from "../../services/matching";
import {
  detectAllAnomalies,
  fetchNetworkBaselineContext,
  fetchStatisticalContextV2,
  type NetworkBaselineDetectorContext,
  type StatisticalContextV2,
} from "../../services/profile/anomaly";
import { loadProfile } from "../../services/matching/profile-loader";
import type { DeviceProfile } from "../../types/profile";
import type { SessionAnomalySignal } from "../../types";
import type { MatchingWorkerEnvConfig } from "../../config/env";
import {
  parseSqsRecord,
  type ParsedRecord,
  type SqsPayload,
} from "./parse-record";
import { recordTierMetric } from "./metrics";
import { emitObservation } from "./observation";
import { writeSessionPayload, buildSessionResponseData } from "./session";
import { archivePayload } from "../ingestion/archive";

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
  /** S3 client for payload archiving (null if archiving disabled) */
  s3: S3Client | null;
  /** S3 bucket name for archived payloads */
  archiveBucket: string | undefined;
  /** Sampling rate for archiving (0.0 to 1.0) */
  archiveSampleRate: number;
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
 * @param networkBaselineContext - Pre-fetched network baseline context for ASN-based detection
 * @param statisticalContextV2 - Pre-fetched statistical v2 context for Shannon scoring
 * @returns Array of anomaly signals for the session
 */
interface AnomalySignalContext {
  fingerprint: ParsedRecord["fingerprint"];
  rawPayload: SqsPayload;
  networkBaseline: NetworkBaselineDetectorContext | null;
  statisticalV2: StatisticalContextV2 | null;
  ipHistoryProfile?: DeviceProfile | null;
}

function buildAnomalySignals(
  ctx: AnomalySignalContext,
): SessionAnomalySignal[] {
  const result = detectAllAnomalies(
    ctx.fingerprint,
    ctx.rawPayload.device,
    undefined,
    {
      networkBaseline: ctx.networkBaseline,
      statisticalV2: ctx.statisticalV2,
      ipHistoryProfile: ctx.ipHistoryProfile ?? null,
    },
  );
  return result.signals.map((s) => ({
    type: s.type,
    code: s.code,
    severity: s.severity,
    evidence: s.evidence,
  }));
}

/** Fire-and-forget archive of enriched session data to S3. */
function archiveEnrichedPayload(
  sessionId: string,
  sessionParams: Parameters<typeof buildSessionResponseData>[0],
  deps: ProcessRecordDeps,
): void {
  const enrichedData = buildSessionResponseData(sessionParams);
  archivePayload(sessionId, enrichedData, {
    s3: deps.s3,
    bucket: deps.archiveBucket,
    sampleRate: deps.archiveSampleRate,
    logger: deps.logger,
    metrics: deps.metrics,
  }).catch(() => {
    /* logged in archivePayload */
  });
}

/** Persist matching results to cache, session table, and profile queue. */
async function persistResults(
  service: MatchingService,
  ctx: {
    sessionId: string;
    matchResult: MatchResult;
    idempotencyKey: string;
    anomalies: SessionAnomalySignal[];
    rawPayload: SqsPayload;
    payload: ParsedRecord["payload"];
    statisticalContextV2: StatisticalContextV2 | null;
  },
  deps: ProcessRecordDeps,
): Promise<void> {
  const { sessionId, matchResult, idempotencyKey, anomalies } = ctx;
  const cacheWritten = await service.writeMatchResult({
    sessionId,
    result: matchResult,
    idempotencyKey,
    anomalies,
  });
  if (!cacheWritten) {
    deps.metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
  }
  const sessionParams = {
    sessionId,
    rawPayload: ctx.rawPayload,
    matchResult,
    anomalies,
    statisticalContextV2: ctx.statisticalContextV2,
  };
  await writeSessionPayload(sessionParams, {
    dynamodb: deps.dynamodb,
    tableName: deps.envConfig.SESSION_PAYLOAD_TABLE,
    logger: deps.logger,
    metrics: deps.metrics,
  });
  archiveEnrichedPayload(sessionId, sessionParams, deps);
  await service.queueProfileUpdate(
    matchResult.device_id,
    ctx.payload,
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

/** Check if session was already processed (cache hit). */
async function checkDuplicate(
  service: MatchingService,
  sessionId: string,
  deps: Pick<ProcessRecordDeps, "logger" | "metrics">,
): Promise<boolean> {
  const cached = await service.cache.checkSessionCache(sessionId);
  if (cached && cached.status === "complete") {
    deps.logger.info("Cache hit - already processed", {
      session_id: sessionId,
      device_id: cached.device_id,
    });
    deps.metrics.addMetric("Tier0CacheHit", MetricUnit.Count, 1);
    return true;
  }
  return false;
}

/** Load profile for IP history anomaly context. Returns null for new devices. */
async function loadProfileForAnomalies(
  deps: ProcessRecordDeps,
  deviceId: string,
): Promise<DeviceProfile | null> {
  try {
    const profileData = await loadProfile(
      {
        dynamodb: deps.dynamodb,
        profilesTable: deps.envConfig.PROFILES_TABLE,
      },
      deviceId,
    );
    return profileData as DeviceProfile | null;
  } catch {
    return null;
  }
}

/** Fetch anomaly contexts and build signals. */
async function fetchAndBuildAnomalies(
  fingerprint: ParsedRecord["fingerprint"],
  rawPayload: SqsPayload,
  ipHistoryProfile?: DeviceProfile | null,
): Promise<{
  anomalies: SessionAnomalySignal[];
  statisticalContextV2: StatisticalContextV2 | null;
}> {
  const [networkBaselineContext, statisticalContextV2] = await Promise.all([
    fetchNetworkBaselineContext(fingerprint, rawPayload.sigint),
    fetchStatisticalContextV2(
      fingerprint,
      rawPayload.sigint,
      rawPayload.device,
      rawPayload.hashes,
    ),
  ]);
  return {
    anomalies: buildAnomalySignals({
      fingerprint,
      rawPayload,
      networkBaseline: networkBaselineContext,
      statisticalV2: statisticalContextV2,
      ipHistoryProfile,
    }),
    statisticalContextV2,
  };
}

/** Process a single SQS record through the matching pipeline. */
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

  if (await checkDuplicate(service, sessionId, deps)) return;

  const { matchResult, tier2TimedOut } = await runMatching(
    service,
    { sessionId, fingerprint, idempotencyKey },
    deps,
  );

  // Load profile for IP history anomaly detection (skip for new devices)
  const existingProfile = matchResult.is_new_device
    ? null
    : await loadProfileForAnomalies(deps, matchResult.device_id);

  const { anomalies, statisticalContextV2 } = await fetchAndBuildAnomalies(
    fingerprint,
    rawPayload,
    existingProfile,
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
      statisticalContextV2,
    },
    deps,
  );

  service.upsertVector(matchResult.device_id, fingerprint).catch((error) => {
    deps.logger.warn("Vector upsert failed", {
      error,
      device_id: matchResult.device_id,
    });
  });
  emitCompletionMetrics(
    { sessionId, matchResult, tier2TimedOut, duration: Date.now() - startTime },
    deps,
  );
}
