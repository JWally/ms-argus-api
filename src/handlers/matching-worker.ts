import { SQSHandler, SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  FingerprintPayload,
  generateIdempotencyKey,
  MatchResult,
} from "../services/matching";
import { DynamoCacheService } from "../services/cache";
import { getMatchingWorkerEnv, MatchingWorkerEnvConfig } from "../config/env";
import {
  SESSION_TTL_SECONDS,
  SESSION_PAYLOAD_TTL_SECONDS,
  TIER2_TIMEOUT_MS,
  MUTATION_GATE_TTL_SECONDS,
} from "../helpers/constants";
import { detectAllAnomalies } from "../services/profile/anomaly";
import type { SessionAnomalySignal } from "../types";
import { gzipSync } from "zlib";
import type { ArgusPayload } from "../helpers/payload-schema";
import { extractFingerprint } from "../services/matching/fingerprint-extractor";

// V3 Payload from ingestion handler (ArgusPayload + metadata)
interface SqsPayload extends ArgusPayload {
  _headers?: Record<string, string>;
  _timestamp?: number;
}

// Validate environment variables at module load (cold start)
// Throws immediately if required env vars are missing
const envConfig: MatchingWorkerEnvConfig = getMatchingWorkerEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
const dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});
const firehose = new FirehoseClient({});

// Service configuration from validated environment
function getConfig(): MatchingServiceConfig {
  return {
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profilesTable: envConfig.PROFILES_TABLE,
    profileQueueUrl: envConfig.PROFILE_QUEUE_URL,
    sessionTtlSeconds: SESSION_TTL_SECONDS,
    tier2TimeoutMs: TIER2_TIMEOUT_MS,
  };
}

// DynamoDB cache service
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

// Create service with production dependencies
function createMatchingService(): MatchingService {
  const deps: MatchingServiceDeps = {
    dynamodb,
    sqs,
    cache: cacheService,
    config: getConfig(),
  };
  return new MatchingService(deps);
}

/**
 * Matching Worker Lambda Handler
 * Processes fingerprints from SQS and writes results to DynamoDB session cache
 */
export const handler: SQSHandler = async (event) => {
  const service = createMatchingService();
  return processSqsBatch(
    event.Records,
    (record) => processRecord(record, service),
    {
      metrics,
      logger,
      successMetric: "MatchingSuccess",
      errorMetric: "MatchingError",
    },
  );
};

/**
 * Check if this is a warmup message from EventBridge
 * Warmup messages keep the SQS polling pipeline active
 */
function isWarmupMessage(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return parsed.warmup === true || parsed.source === "warmup-rule";
  } catch {
    return false;
  }
}

/**
 * Process a single SQS record
 */
async function processRecord(
  record: SQSRecord,
  service: MatchingService,
): Promise<void> {
  if (isWarmupMessage(record.body)) {
    logger.info("Warmup ping received - keeping pipeline warm");
    metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return;
  }

  const startTime = Date.now();

  // Don't retry malformed JSON - treat as poison message
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
    return;
  }

  // V3 format: extract session_id from identifiers
  const session_id = rawPayload.identifiers?.session_id;
  if (!session_id) {
    logger.error("Missing session_id in payload", {
      messageId: record.messageId,
    });
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    return;
  }

  // Extract flat fingerprint from V3 payload (with header fallback for IP)
  const fingerprint = extractFingerprint(rawPayload, rawPayload._headers);

  // Build legacy payload format for downstream compatibility
  const payload: FingerprintPayload = {
    session_id,
    fingerprint,
    sigint: rawPayload.sigint as FingerprintPayload["sigint"],
    headers: rawPayload._headers || {},
    timestamp: rawPayload._timestamp || Date.now(),
  };

  logger.info("Processing fingerprint", { session_id });

  // Generate idempotency key for dedup
  const idempotencyKey = generateIdempotencyKey(session_id, fingerprint);

  // Check if already processed (Tier 0 - DynamoDB session cache)
  const cached = await service.checkCache(session_id);
  if (cached && cached.status === "complete") {
    logger.info("Cache hit - already processed", {
      session_id,
      device_id: cached.device_id,
    });
    metrics.addMetric("Tier0CacheHit", MetricUnit.Count, 1);
    return;
  }

  // Run tiered matching
  let matchResult;
  let tier2TimedOut = false;
  try {
    const matchResponse = await service.runTieredMatching(fingerprint);
    matchResult = matchResponse.result;
    tier2TimedOut = matchResponse.tier2TimedOut;
    recordTierMetric(matchResult.match_tier, matchResult.is_new_device);

    // Track Tier2 timeouts for monitoring "fail open" scenarios
    if (tier2TimedOut) {
      metrics.addMetric("Tier2Timeout", MetricUnit.Count, 1);
      logger.warn("Tier2 matching timed out", { session_id });
    }
  } catch (error) {
    // On matching failure, write degraded status
    logger.error("Matching failed", { error, session_id });
    const degradedWritten = await service.writeDegradedResult(
      session_id,
      idempotencyKey,
    );
    if (!degradedWritten) {
      metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
    }
    throw error;
  }

  // Run anomaly detection on fingerprint
  const anomalyResult = detectAllAnomalies(
    fingerprint,
    rawPayload.device, // Raw device data for cross-field checks
    undefined, // sigint - no geo.timezone available yet
  );

  // Convert anomaly signals to session format
  const anomalies: SessionAnomalySignal[] = anomalyResult.signals.map((s) => ({
    type: s.type,
    code: s.code,
    severity: s.severity,
    evidence: s.evidence,
  }));

  // Write result to DynamoDB session cache (now with anomalies)
  const cacheWritten = await service.writeMatchResult(
    session_id,
    matchResult,
    idempotencyKey,
    anomalies,
  );
  if (!cacheWritten) {
    metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
    logger.info("Session cache write skipped (higher confidence exists)", {
      session_id,
      confidence: matchResult.confidence,
    });
  }

  // Write full payload to session payload table
  await writeSessionPayload(
    session_id,
    payload,
    rawPayload,
    matchResult,
    anomalies,
  );

  // Queue profile update
  await service.queueProfileUpdate(
    matchResult.device_id,
    payload,
    matchResult.is_new_device,
    matchResult,
  );

  const duration = Date.now() - startTime;
  metrics.addMetric("MatchingDuration", MetricUnit.Milliseconds, duration);

  // Emit observation to Firehose (fire-and-forget)
  emitObservation({
    sessionId: session_id,
    matchResult,
    tier2TimedOut,
    durationMs: duration,
  }).catch(() => {
    // Error already logged in emitObservation
  });

  logger.info("Matching complete", {
    session_id,
    device_id: matchResult.device_id,
    duration,
    tier: matchResult.match_tier,
  });
}

const TIER_METRICS: Record<number, string[]> = {
  0.5: ["Tier05Hit"],
  1: ["Tier1Hit"],
  2: ["Tier2Hit"],
  3: ["Tier3Hit"],
};

const NEW_DEVICE_METRICS = [
  "NewDevice",
  "NEW_DEVICE_RATE",
  "DeviceIdFormat_ulid",
];

function recordTierMetric(tier: number, isNewDevice: boolean): void {
  const names = isNewDevice ? NEW_DEVICE_METRICS : (TIER_METRICS[tier] ?? []);
  for (const name of names) {
    metrics.addMetric(name, MetricUnit.Count, 1);
  }
}

/**
 * Emit match observation to Firehose for analytics
 */
async function emitObservation(params: {
  sessionId: string;
  matchResult: MatchResult;
  tier2TimedOut: boolean;
  durationMs: number;
}): Promise<void> {
  if (!envConfig.OBSERVATIONS_STREAM_NAME) {
    return;
  }

  const observation = {
    session_id: params.sessionId,
    device_id: params.matchResult.device_id,
    match_tier: params.matchResult.match_tier,
    is_new_device: params.matchResult.is_new_device,
    tier2_timed_out: params.tier2TimedOut,
    duration_ms: params.durationMs,
    timestamp: new Date().toISOString(),
  };

  try {
    await firehose.send(
      new PutRecordCommand({
        DeliveryStreamName: envConfig.OBSERVATIONS_STREAM_NAME,
        Record: {
          Data: Buffer.from(JSON.stringify(observation) + "\n"),
        },
      }),
    );
  } catch (error) {
    logger.warn("Failed to emit observation to Firehose", {
      error,
      sessionId: params.sessionId,
    });
    metrics.addMetric("ObservationEmitError", MetricUnit.Count, 1);
  }
}

/**
 * Write full fingerprint payload to session payload table
 * Enables session-get endpoint to return complete data
 * Uses gzipped base64 storage for efficiency
 */
async function writeSessionPayload(
  sessionId: string,
  payload: FingerprintPayload,
  rawPayload: SqsPayload,
  matchResult: MatchResult,
  anomalies: SessionAnomalySignal[],
): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + SESSION_PAYLOAD_TTL_SECONDS;

  try {
    // Build identifiers section
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

    // Build analysis section
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

    // Build complete response payload matching V3 response schema
    const fullData = {
      identifiers,
      analysis,
      hashes: rawPayload.hashes,
      device: rawPayload.device,
      sigint: rawPayload.sigint,
    };

    // Gzip and base64 encode
    const payloadJson = JSON.stringify(fullData);
    const gzipped = gzipSync(Buffer.from(payloadJson));
    const payloadGzipB64 = gzipped.toString("base64");

    await dynamodb.send(
      new PutItemCommand({
        TableName: envConfig.SESSION_PAYLOAD_TABLE,
        Item: {
          session_id: { S: sessionId },
          payload_gzip_b64: { S: payloadGzipB64 },
          ttl: { N: String(ttl) },
          created_at: { S: new Date().toISOString() },
        },
      }),
    );
  } catch (error) {
    logger.warn("Failed to write session payload", {
      error,
      sessionId,
    });
    metrics.addMetric("SessionPayloadWriteError", MetricUnit.Count, 1);
  }
}
