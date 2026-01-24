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
// Supports both V2 "network" and V3 "sigint" field names
interface SqsPayload extends ArgusPayload {
  _headers?: Record<string, string>;
  _timestamp?: number;
  network?: ArgusPayload["sigint"]; // V2 compat
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
interface ParsedRecord {
  rawPayload: SqsPayload;
  sessionId: string;
  fingerprint: ReturnType<typeof extractFingerprint>;
  payload: FingerprintPayload;
}

function parseSqsRecord(record: SQSRecord): ParsedRecord | null {
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

async function runMatching(
  service: MatchingService,
  sessionId: string,
  fingerprint: ParsedRecord["fingerprint"],
  idempotencyKey: string,
): Promise<{ matchResult: MatchResult; tier2TimedOut: boolean }> {
  try {
    const response = await service.runTieredMatching(fingerprint);
    recordTierMetric(response.result.match_tier, response.result.is_new_device);
    if (response.tier2TimedOut) {
      metrics.addMetric("Tier2Timeout", MetricUnit.Count, 1);
      logger.warn("Tier2 matching timed out", { session_id: sessionId });
    }
    return {
      matchResult: response.result,
      tier2TimedOut: response.tier2TimedOut,
    };
  } catch (error) {
    logger.error("Matching failed", { error, session_id: sessionId });
    const written = await service.writeDegradedResult(
      sessionId,
      idempotencyKey,
    );
    if (!written) {
      metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
    }
    throw error;
  }
}

async function processRecord(
  record: SQSRecord,
  service: MatchingService,
): Promise<void> {
  const parsed = parseSqsRecord(record);
  if (!parsed) return;

  const startTime = Date.now();
  const { rawPayload, sessionId, fingerprint, payload } = parsed;

  logger.info("Processing fingerprint", { session_id: sessionId });
  const idempotencyKey = generateIdempotencyKey(sessionId, fingerprint);

  const cached = await service.checkCache(sessionId);
  if (cached && cached.status === "complete") {
    logger.info("Cache hit - already processed", {
      session_id: sessionId,
      device_id: cached.device_id,
    });
    metrics.addMetric("Tier0CacheHit", MetricUnit.Count, 1);
    return;
  }

  const { matchResult, tier2TimedOut } = await runMatching(
    service,
    sessionId,
    fingerprint,
    idempotencyKey,
  );

  const anomalyResult = detectAllAnomalies(fingerprint, rawPayload.device);
  const anomalies: SessionAnomalySignal[] = anomalyResult.signals.map((s) => ({
    type: s.type,
    code: s.code,
    severity: s.severity,
    evidence: s.evidence,
  }));

  const cacheWritten = await service.writeMatchResult({
    sessionId,
    result: matchResult,
    idempotencyKey,
    anomalies,
  });
  if (!cacheWritten) {
    metrics.addMetric("SessionCacheWriteSkipped", MetricUnit.Count, 1);
  }

  await writeSessionPayload({ sessionId, rawPayload, matchResult, anomalies });
  await service.queueProfileUpdate(
    matchResult.device_id,
    payload,
    matchResult.is_new_device,
    matchResult,
  );

  const duration = Date.now() - startTime;
  metrics.addMetric("MatchingDuration", MetricUnit.Milliseconds, duration);

  emitObservation({
    sessionId,
    matchResult,
    tier2TimedOut,
    durationMs: duration,
  }).catch(() => {
    /* logged in emitObservation */
  });

  logger.info("Matching complete", {
    session_id: sessionId,
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

/**
 * Write full fingerprint payload to session payload table
 * Uses gzipped base64 storage for efficiency
 */
async function writeSessionPayload(params: {
  sessionId: string;
  rawPayload: SqsPayload;
  matchResult: MatchResult;
  anomalies: SessionAnomalySignal[];
}): Promise<void> {
  const { sessionId } = params;
  const ttl = Math.floor(Date.now() / 1000) + SESSION_PAYLOAD_TTL_SECONDS;

  try {
    const fullData = buildSessionResponseData(params);
    const gzipped = gzipSync(Buffer.from(JSON.stringify(fullData)));
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
    logger.warn("Failed to write session payload", { error, sessionId });
    metrics.addMetric("SessionPayloadWriteError", MetricUnit.Count, 1);
  }
}
