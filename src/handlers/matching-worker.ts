// src/handlers/matching-worker.ts
import { SQSHandler, SQSBatchResponse, SQSBatchItemFailure, SQSRecord } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { Metrics, MetricUnit } from '@aws-lambda-powertools/metrics';
import { DynamoDBClient, GetItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import Redis from 'ioredis';

const logger = new Logger({ serviceName: process.env.POWERTOOLS_SERVICE_NAME });
const tracer = new Tracer({ serviceName: process.env.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({ namespace: process.env.POWERTOOLS_METRICS_NAMESPACE });

// Clients (reused across invocations)
const dynamodb = tracer.captureAWSv3Client(new DynamoDBClient({}));
const sqs = tracer.captureAWSv3Client(new SQSClient({}));

// Redis connection (lazy initialized, reused)
let redis: Redis | null = null;

function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      host: process.env.REDIS_ENDPOINT!,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      tls: {},
      maxRetriesPerRequest: 3,
      retryStrategy: (times: number) => Math.min(times * 100, 2000),
    });
  }
  return redis;
}

// Session cache value structure
interface SessionCacheValue {
  status: 'pending' | 'complete' | 'degraded';
  device_id: string;
  risk_score: number;
  confidence: number;
  match_tier: number;
  match_version: number;
  idempotency_key: string;
  flags: string[];
  updated_at: number;
}

// Fingerprint payload from SQS
interface FingerprintPayload {
  session_id: string;
  tenant_id: string;
  fingerprint: {
    stable_hash?: string;
    fuzzy_hash?: string;
    canvas_hash?: string;
    webgl_hash?: string;
    audio_hash?: string;
    ip_address?: string;
    ja4?: string;
    gpu_renderer?: string;
    screen_dims?: string;
    timezone?: string;
    evercookie_id?: string;
    // ... other fingerprint fields
  };
  tcp_blob?: string;
  tls_blob?: string;
  headers: Record<string, string>;
  timestamp: number;
}

// Match result
interface MatchResult {
  device_id: string;
  confidence: number;
  match_tier: number;
  is_new_device: boolean;
  risk_score: number;
  flags: string[];
}

/**
 * Matching Worker Lambda Handler
 * Processes fingerprints from SQS and writes results to Redis
 */
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];

  for (const record of event.Records) {
    try {
      await processRecord(record);
      metrics.addMetric('MatchingSuccess', MetricUnit.Count, 1);
    } catch (error) {
      logger.error('Failed to process record', { error, messageId: record.messageId });
      metrics.addMetric('MatchingError', MetricUnit.Count, 1);
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }

  metrics.publishStoredMetrics();
  return { batchItemFailures };
};

async function processRecord(record: SQSRecord): Promise<void> {
  const startTime = Date.now();
  const payload: FingerprintPayload = JSON.parse(record.body);
  const { session_id, tenant_id, fingerprint } = payload;

  logger.info('Processing fingerprint', { session_id, tenant_id });

  // Generate idempotency key for dedup
  const idempotencyKey = generateIdempotencyKey(session_id, fingerprint);

  // Check if already processed (Tier 0 - Redis cache)
  const cached = await checkCache(session_id);
  if (cached && cached.status === 'complete') {
    logger.info('Cache hit - already processed', { session_id, device_id: cached.device_id });
    metrics.addMetric('Tier0CacheHit', MetricUnit.Count, 1);
    return;
  }

  // Run tiered matching
  let matchResult: MatchResult;
  try {
    matchResult = await runTieredMatching(tenant_id, fingerprint);
  } catch (error) {
    // On matching failure, write degraded status
    logger.error('Matching failed', { error, session_id });
    await writeDegradedResult(session_id, idempotencyKey);
    throw error;
  }

  // Write result to Redis
  await writeMatchResult(session_id, matchResult, idempotencyKey);

  // Queue profile update
  await queueProfileUpdate(tenant_id, matchResult.device_id, payload);

  const duration = Date.now() - startTime;
  metrics.addMetric('MatchingDuration', MetricUnit.Milliseconds, duration);
  logger.info('Matching complete', { session_id, device_id: matchResult.device_id, duration, tier: matchResult.match_tier });
}

async function checkCache(sessionId: string): Promise<SessionCacheValue | null> {
  const redis = getRedis();
  const key = `session:${sessionId}`;
  const cached = await redis.get(key);
  return cached ? JSON.parse(cached) : null;
}

async function runTieredMatching(tenantId: string, fingerprint: FingerprintPayload['fingerprint']): Promise<MatchResult> {
  // Tier 0.5: Evercookie/Cookie lookup
  if (fingerprint.evercookie_id) {
    const result = await tier05CookieLookup(tenantId, fingerprint.evercookie_id);
    if (result) {
      metrics.addMetric('Tier05Hit', MetricUnit.Count, 1);
      return result;
    }
  }

  // Tier 1: Strong hash match
  const tier1Result = await tier1HashMatch(tenantId, fingerprint);
  if (tier1Result) {
    metrics.addMetric('Tier1Hit', MetricUnit.Count, 1);
    return tier1Result;
  }

  // Tier 2: Compound filter match (with 100ms timeout)
  const tier2Result = await Promise.race([
    tier2CompoundMatch(tenantId, fingerprint),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), 100)),
  ]);
  if (tier2Result) {
    metrics.addMetric('Tier2Hit', MetricUnit.Count, 1);
    return tier2Result;
  }

  // Tier 3: Vector similarity (placeholder - Qdrant integration)
  // TODO: Implement when Qdrant stack is deployed
  // const tier3Result = await tier3VectorMatch(tenantId, fingerprint);
  // if (tier3Result) {
  //   metrics.addMetric('Tier3Hit', MetricUnit.Count, 1);
  //   return tier3Result;
  // }

  // New device
  metrics.addMetric('NewDevice', MetricUnit.Count, 1);
  return createNewDevice(tenantId, fingerprint);
}

async function tier05CookieLookup(tenantId: string, evercookieId: string): Promise<MatchResult | null> {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: process.env.TIER1_INDEX_TABLE,
      Key: {
        tenant_id: { S: tenantId },
        hash_key: { S: `evercookie#${evercookieId}` },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      confidence: 0.99,
      match_tier: 0.5,
      is_new_device: false,
      risk_score: item.risk_score || 0.3,
      flags: item.flags || [],
    };
  }
  return null;
}

async function tier1HashMatch(tenantId: string, fingerprint: FingerprintPayload['fingerprint']): Promise<MatchResult | null> {
  // Try stable hash first
  if (fingerprint.stable_hash) {
    const result = await dynamodb.send(
      new GetItemCommand({
        TableName: process.env.TIER1_INDEX_TABLE,
        Key: {
          tenant_id: { S: tenantId },
          hash_key: { S: `stable#${fingerprint.stable_hash}` },
        },
      }),
    );

    if (result.Item) {
      const item = unmarshall(result.Item);
      return {
        device_id: item.device_id,
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: item.risk_score || 0.3,
        flags: item.flags || [],
      };
    }
  }

  // Try fuzzy hash
  if (fingerprint.fuzzy_hash) {
    const result = await dynamodb.send(
      new GetItemCommand({
        TableName: process.env.TIER1_INDEX_TABLE,
        Key: {
          tenant_id: { S: tenantId },
          hash_key: { S: `fuzzy#${fingerprint.fuzzy_hash}` },
        },
      }),
    );

    if (result.Item) {
      const item = unmarshall(result.Item);
      return {
        device_id: item.device_id,
        confidence: 0.85,
        match_tier: 1,
        is_new_device: false,
        risk_score: item.risk_score || 0.3,
        flags: item.flags || [],
      };
    }
  }

  return null;
}

async function tier2CompoundMatch(tenantId: string, fingerprint: FingerprintPayload['fingerprint']): Promise<MatchResult | null> {
  // Build compound bucket keys
  const bucketKeys: string[] = [];

  if (fingerprint.ip_address && fingerprint.ja4) {
    bucketKeys.push(`${tenantId}#ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`);
  }
  if (fingerprint.gpu_renderer && fingerprint.screen_dims && fingerprint.timezone) {
    bucketKeys.push(`${tenantId}#gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`);
  }
  if (fingerprint.audio_hash && fingerprint.canvas_hash) {
    bucketKeys.push(`${tenantId}#audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`);
  }

  if (bucketKeys.length === 0) return null;

  // Query all buckets in parallel
  const queries = bucketKeys.map((key) =>
    dynamodb.send(
      new GetItemCommand({
        TableName: process.env.TIER2_BUCKETS_TABLE,
        Key: { bucket_key: { S: key } },
      }),
    ),
  );

  const results = await Promise.all(queries);
  const candidates: Map<string, number> = new Map();

  // Count device_id occurrences across buckets
  for (const result of results) {
    if (result.Item) {
      const item = unmarshall(result.Item);
      const deviceIds: string[] = item.device_ids || [];
      for (const deviceId of deviceIds) {
        candidates.set(deviceId, (candidates.get(deviceId) || 0) + 1);
      }
    }
  }

  // Find best match (highest bucket overlap)
  let bestDeviceId: string | null = null;
  let bestScore = 0;

  for (const [deviceId, score] of candidates) {
    if (score > bestScore) {
      bestScore = score;
      bestDeviceId = deviceId;
    }
  }

  // Require at least 2 bucket matches
  if (bestDeviceId && bestScore >= 2) {
    // Load profile to get risk score
    const profile = await loadProfile(tenantId, bestDeviceId);
    return {
      device_id: bestDeviceId,
      confidence: Math.min(0.6 + bestScore * 0.1, 0.85),
      match_tier: 2,
      is_new_device: false,
      risk_score: profile?.risk_score || 0.4,
      flags: profile?.flags || [],
    };
  }

  return null;
}

async function loadProfile(tenantId: string, deviceId: string): Promise<{ risk_score: number; flags: string[] } | null> {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: process.env.PROFILES_TABLE,
      Key: {
        tenant_id: { S: tenantId },
        device_id: { S: deviceId },
      },
      ProjectionExpression: 'risk_score, flags',
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return { risk_score: item.risk_score, flags: item.flags || [] };
  }
  return null;
}

function createNewDevice(tenantId: string, fingerprint: FingerprintPayload['fingerprint']): MatchResult {
  const deviceId = `dev_${generateUUID()}`;
  return {
    device_id: deviceId,
    confidence: 1.0,
    match_tier: -1, // New device
    is_new_device: true,
    risk_score: 0.5, // Neutral for new devices
    flags: [],
  };
}

async function writeMatchResult(sessionId: string, result: MatchResult, idempotencyKey: string): Promise<void> {
  const redis = getRedis();
  const key = `session:${sessionId}`;

  const value: SessionCacheValue = {
    status: 'complete',
    device_id: result.device_id,
    risk_score: result.risk_score,
    confidence: result.confidence,
    match_tier: result.match_tier,
    match_version: Date.now(),
    idempotency_key: idempotencyKey,
    flags: result.flags,
    updated_at: Date.now(),
  };

  // Use SETNX-style logic: only write if better match or no existing value
  const existing = await redis.get(key);
  if (existing) {
    const existingValue: SessionCacheValue = JSON.parse(existing);
    // Only overwrite if new result has higher confidence
    if (existingValue.confidence >= result.confidence && existingValue.status === 'complete') {
      logger.info('Skipping write - existing match is better', { sessionId, existing: existingValue.confidence, new: result.confidence });
      return;
    }
  }

  await redis.setex(key, 900, JSON.stringify(value)); // 15 min TTL
}

async function writeDegradedResult(sessionId: string, idempotencyKey: string): Promise<void> {
  const redis = getRedis();
  const key = `session:${sessionId}`;

  const value: SessionCacheValue = {
    status: 'degraded',
    device_id: '',
    risk_score: 0.5,
    confidence: 0,
    match_tier: -1,
    match_version: Date.now(),
    idempotency_key: idempotencyKey,
    flags: ['matching_failed'],
    updated_at: Date.now(),
  };

  await redis.setex(key, 900, JSON.stringify(value));
}

async function queueProfileUpdate(tenantId: string, deviceId: string, payload: FingerprintPayload): Promise<void> {
  await sqs.send(
    new SendMessageCommand({
      QueueUrl: process.env.PROFILE_QUEUE_URL,
      MessageBody: JSON.stringify({
        tenant_id: tenantId,
        device_id: deviceId,
        fingerprint: payload.fingerprint,
        tcp_blob: payload.tcp_blob,
        tls_blob: payload.tls_blob,
        timestamp: payload.timestamp,
      }),
    }),
  );
}

function generateIdempotencyKey(sessionId: string, fingerprint: FingerprintPayload['fingerprint']): string {
  // FNV-1a hash of session_id + stable fingerprint components
  const input = `${sessionId}:${fingerprint.stable_hash || ''}:${fingerprint.canvas_hash || ''}`;
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
