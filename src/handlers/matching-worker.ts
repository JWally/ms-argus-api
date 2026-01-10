// src/handlers/matching-worker.ts
import { SQSHandler, SQSBatchResponse, SQSBatchItemFailure, SQSRecord } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
// import { Tracer } from '@aws-lambda-powertools/tracer'; // Disabled due to @smithy bundling issues
import { Metrics, MetricUnit } from '@aws-lambda-powertools/metrics';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { SQSClient } from '@aws-sdk/client-sqs';
import Redis from 'ioredis';
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  FingerprintPayload,
  generateIdempotencyKey,
} from '../services/matching';

// Powertools
const logger = new Logger({ serviceName: process.env.POWERTOOLS_SERVICE_NAME });
// const tracer = new Tracer({ serviceName: process.env.POWERTOOLS_SERVICE_NAME }); // Disabled
const metrics = new Metrics({ namespace: process.env.POWERTOOLS_METRICS_NAMESPACE });

// AWS SDK clients (reused across invocations)
// Note: Tracer capture disabled temporarily due to bundling issues with @smithy
const dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});

// Redis client (lazy initialized, reused)
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

// Service configuration from environment
function getConfig(): MatchingServiceConfig {
  return {
    tier1IndexTable: process.env.TIER1_INDEX_TABLE!,
    tier2BucketsTable: process.env.TIER2_BUCKETS_TABLE!,
    profilesTable: process.env.PROFILES_TABLE!,
    profileQueueUrl: process.env.PROFILE_QUEUE_URL!,
    sessionTtlSeconds: 900, // 15 minutes
    tier2TimeoutMs: 100,
  };
}

// Create service with production dependencies
function createMatchingService(): MatchingService {
  const deps: MatchingServiceDeps = {
    dynamodb,
    sqs,
    redis: getRedis(),
    config: getConfig(),
  };
  return new MatchingService(deps);
}

/**
 * Matching Worker Lambda Handler
 * Processes fingerprints from SQS and writes results to Redis
 */
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];
  const service = createMatchingService();

  for (const record of event.Records) {
    try {
      await processRecord(record, service);
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

/**
 * Process a single SQS record
 */
async function processRecord(record: SQSRecord, service: MatchingService): Promise<void> {
  const startTime = Date.now();
  const payload: FingerprintPayload = JSON.parse(record.body);
  const { session_id, tenant_id, fingerprint } = payload;

  logger.info('Processing fingerprint', { session_id, tenant_id });

  // Generate idempotency key for dedup
  const idempotencyKey = generateIdempotencyKey(session_id, fingerprint);

  // Check if already processed (Tier 0 - Redis cache)
  const cached = await service.checkCache(session_id);
  if (cached && cached.status === 'complete') {
    logger.info('Cache hit - already processed', { session_id, device_id: cached.device_id });
    metrics.addMetric('Tier0CacheHit', MetricUnit.Count, 1);
    return;
  }

  // Run tiered matching
  let matchResult;
  try {
    matchResult = await service.runTieredMatching(tenant_id, fingerprint);
    recordTierMetric(matchResult.match_tier, matchResult.is_new_device);
  } catch (error) {
    // On matching failure, write degraded status
    logger.error('Matching failed', { error, session_id });
    await service.writeDegradedResult(session_id, idempotencyKey);
    throw error;
  }

  // Write result to Redis
  await service.writeMatchResult(session_id, matchResult, idempotencyKey);

  // Queue profile update
  await service.queueProfileUpdate(tenant_id, matchResult.device_id, payload);

  const duration = Date.now() - startTime;
  metrics.addMetric('MatchingDuration', MetricUnit.Milliseconds, duration);
  logger.info('Matching complete', {
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
    metrics.addMetric('NewDevice', MetricUnit.Count, 1);
  } else if (tier === 0.5) {
    metrics.addMetric('Tier05Hit', MetricUnit.Count, 1);
  } else if (tier === 1) {
    metrics.addMetric('Tier1Hit', MetricUnit.Count, 1);
  } else if (tier === 2) {
    metrics.addMetric('Tier2Hit', MetricUnit.Count, 1);
  } else if (tier === 3) {
    metrics.addMetric('Tier3Hit', MetricUnit.Count, 1);
  }
}
