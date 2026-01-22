// src/handlers/matching-worker.ts
// AR-52: Replaced Redis with DynamoDB session cache
// AR-57: Added Firehose observations for analytics
// AR-71: Added warmup detection for SQS pipeline warming
// AR-73: Added fingerprint normalization for web library compatibility
// AR-148: Added anomaly detection for session response
// AR-XXX: V3 payload schema - simplified, no V1/V2 detection
import {
  SQSHandler,
  SQSBatchResponse,
  SQSBatchItemFailure,
  SQSRecord,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
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
import type { SessionAnomalySignal, Fingerprint } from "../types";
import { gzipSync } from "zlib";
import type { ArgusPayload } from "../helpers/payload-schema";

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
const firehose = new FirehoseClient({}); // AR-57: For observations

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

// Create DynamoDB cache service (AR-52: replaces Redis)
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
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];
  const service = createMatchingService();

  for (const record of event.Records) {
    try {
      await processRecord(record, service);
      metrics.addMetric("MatchingSuccess", MetricUnit.Count, 1);
    } catch (error) {
      logger.error("Failed to process record", {
        error,
        messageId: record.messageId,
      });
      metrics.addMetric("MatchingError", MetricUnit.Count, 1);
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }

  metrics.publishStoredMetrics();
  return { batchItemFailures };
};

/**
 * AR-71: Check if this is a warmup message from EventBridge
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
 * Extract flat fingerprint fields from V3 device section
 * The device section contains nested objects per component (workerScope, navigator, etc.)
 * We extract the relevant fields for matching into a flat Fingerprint object
 */
function extractFingerprint(payload: SqsPayload): Fingerprint {
  const { hashes, device, sigint, identifiers } = payload;

  // Start with core hashes
  const fingerprint: Fingerprint = {
    stable_hash: hashes.stable,
    fuzzy_hash: hashes.fuzzy,
  };

  // Extract identifiers
  if (identifiers.evercookie_id) {
    fingerprint.evercookie_id = identifiers.evercookie_id;
  }
  if (identifiers.public_key) {
    fingerprint.public_key = identifiers.public_key;
  }

  // Extract from workerScope component (browser/device info)
  const workerScope = device.workerScope;
  if (workerScope) {
    if (typeof workerScope.userAgent === "string") {
      fingerprint.user_agent = workerScope.userAgent;
    }
    if (typeof workerScope.hardwareConcurrency === "number") {
      fingerprint.hardware_concurrency = workerScope.hardwareConcurrency;
    }
    if (typeof workerScope.deviceMemory === "number") {
      fingerprint.device_memory = workerScope.deviceMemory;
    }
    if (typeof workerScope.webglRenderer === "string") {
      fingerprint.gpu_renderer = workerScope.webglRenderer;
    }
    if (typeof workerScope.timezoneLocation === "string") {
      fingerprint.timezone = workerScope.timezoneLocation;
    }
  }

  // Extract from screen component
  const screen = device.screen;
  if (screen) {
    const width = screen.width;
    const height = screen.height;
    if (typeof width === "number" && typeof height === "number") {
      fingerprint.screen_dims = `${width}x${height}`;
    }
  }

  // Extract canvas hash
  if (hashes.canvas2d) {
    fingerprint.canvas_hash = hashes.canvas2d;
  }

  // Extract webgl hash
  if (hashes.canvasWebgl) {
    fingerprint.webgl_hash = hashes.canvasWebgl;
  }

  // Extract audio hash
  if (hashes.offlineAudioContext) {
    fingerprint.audio_hash = hashes.offlineAudioContext;
  }

  // Extract maths hash (for structural anchors)
  if (hashes.maths) {
    fingerprint.maths_hash = hashes.maths;
  }

  // Extract from sigint (network intelligence)
  if (sigint) {
    if (sigint.tlsFingerprint) {
      const tls = sigint.tlsFingerprint;
      if (tls.ip) fingerprint.ip_address = tls.ip;
      if (tls.ja3) fingerprint.ja3 = tls.ja3;
      if (tls.ja4) fingerprint.ja4 = tls.ja4;
      if (tls.id) fingerprint.sigint_id = tls.id;
    }
    if (sigint.tcpProbe) {
      const tcp = sigint.tcpProbe as Record<string, unknown>;
      // Handle both flat structure (proxyScore) and nested structure (rtt_fingerprint.proxy_score)
      const rttFp = tcp.rtt_fingerprint as Record<string, unknown> | undefined;
      if (rttFp) {
        // Web client sends nested rtt_fingerprint object
        if (typeof rttFp.proxy_score === "number") {
          fingerprint.proxy_score = rttFp.proxy_score;
        }
        if (typeof rttFp.vpn_score === "number") {
          fingerprint.vpn_score = rttFp.vpn_score;
        }
        if (typeof rttFp.tcp_rtt_us === "number") {
          fingerprint.tcp_rtt_us = rttFp.tcp_rtt_us;
        }
      } else {
        // Fallback to flat structure for backwards compatibility
        if (typeof tcp.proxyScore === "number") {
          fingerprint.proxy_score = tcp.proxyScore;
        }
        if (typeof tcp.vpnScore === "number") {
          fingerprint.vpn_score = tcp.vpnScore;
        }
        if (typeof tcp.rttMs === "number") {
          fingerprint.tcp_rtt_us = (tcp.rttMs as number) * 1000;
        }
      }
    }
    if (sigint.faviconCache?.id) {
      // Use favicon cache ID as an additional identity signal
      fingerprint.favicon_cache_id = sigint.faviconCache.id;
    }
    // Extract STUN data - handle both field naming conventions
    const stun = sigint.stun as Record<string, unknown> | undefined;
    if (stun) {
      // Web sends reflexiveIp, API schema expects publicIp
      const publicIp = stun.publicIp ?? stun.reflexiveIp;
      if (typeof publicIp === "string") {
        fingerprint.stun_public_ip = publicIp;
      }
      // Web sends localIp (string), API schema expects localIps (array)
      const localIp =
        stun.localIp ?? (stun.localIps as string[] | undefined)?.[0];
      if (typeof localIp === "string") {
        fingerprint.stun_local_ip = localIp;
      }
    }
  }

  // Extract headless/bot detection signals
  const headless = device.headless as Record<string, unknown> | undefined;
  if (headless) {
    // Handle direct isHeadless boolean
    if (typeof headless.isHeadless === "boolean") {
      fingerprint.is_headless = headless.isHeadless;
    } else {
      // Web client sends headless.headless object with individual signals
      // Compute isHeadless from the nested headless signals
      const headlessSignals = headless.headless as
        | Record<string, boolean>
        | undefined;
      if (headlessSignals) {
        fingerprint.is_headless = Object.values(headlessSignals).some(Boolean);
      }
    }
  }

  const lies = device.lies as Record<string, unknown> | undefined;
  if (lies) {
    // Handle both field names: count (API schema) and totalLies (web client)
    if (typeof lies.count === "number") {
      fingerprint.lie_count = lies.count;
    } else if (typeof lies.totalLies === "number") {
      fingerprint.lie_count = lies.totalLies;
    }
  }

  return fingerprint;
}

/**
 * Process a single SQS record
 */
async function processRecord(
  record: SQSRecord,
  service: MatchingService,
): Promise<void> {
  // AR-71: Handle warmup messages - just log and return
  if (isWarmupMessage(record.body)) {
    logger.info("Warmup ping received - keeping pipeline warm");
    metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return;
  }

  const startTime = Date.now();

  // AR-156: Handle malformed JSON payloads - don't retry poison messages
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

  // Extract flat fingerprint from V3 payload
  const fingerprint = extractFingerprint(rawPayload);

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

  // AR-148: Run anomaly detection on fingerprint
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

  // AR-57: Emit observation to Firehose (fire-and-forget)
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

/**
 * Record metric for which tier matched
 */
function recordTierMetric(tier: number, isNewDevice: boolean): void {
  if (isNewDevice) {
    metrics.addMetric("NewDevice", MetricUnit.Count, 1);
    metrics.addMetric("NEW_DEVICE_RATE", MetricUnit.Count, 1);
    metrics.addMetric("DeviceIdFormat_ulid", MetricUnit.Count, 1);
  } else if (tier === 0.5) {
    metrics.addMetric("Tier05Hit", MetricUnit.Count, 1);
  } else if (tier === 1) {
    metrics.addMetric("Tier1Hit", MetricUnit.Count, 1);
  } else if (tier === 2) {
    metrics.addMetric("Tier2Hit", MetricUnit.Count, 1);
  } else if (tier === 3) {
    metrics.addMetric("Tier3Hit", MetricUnit.Count, 1);
  }
}

/**
 * AR-57: Emit match observation to Firehose for analytics
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
