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
import { detectAllAnomalies } from "../../services/profile/anomaly";
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

export interface ProcessRecordDeps {
  logger: Logger;
  metrics: Metrics;
  dynamodb: DynamoDBClient;
  firehose: FirehoseClient;
  envConfig: MatchingWorkerEnvConfig;
}

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

function buildAnomalySignals(
  fingerprint: ParsedRecord["fingerprint"],
  rawPayload: SqsPayload,
): SessionAnomalySignal[] {
  const result = detectAllAnomalies(fingerprint, rawPayload.device);
  return result.signals.map((s) => ({
    type: s.type,
    code: s.code,
    severity: s.severity,
    evidence: s.evidence,
  }));
}

async function persistResults(
  service: MatchingService,
  ctx: {
    sessionId: string;
    matchResult: MatchResult;
    idempotencyKey: string;
    anomalies: SessionAnomalySignal[];
    rawPayload: SqsPayload;
    payload: ParsedRecord["payload"];
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
    { sessionId, rawPayload, matchResult, anomalies },
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

  const cached = await service.checkCache(sessionId);
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

  const anomalies = buildAnomalySignals(fingerprint, rawPayload);
  await persistResults(
    service,
    { sessionId, matchResult, idempotencyKey, anomalies, rawPayload, payload },
    deps,
  );

  const duration = Date.now() - startTime;
  emitCompletionMetrics(
    { sessionId, matchResult, tier2TimedOut, duration },
    deps,
  );
}
