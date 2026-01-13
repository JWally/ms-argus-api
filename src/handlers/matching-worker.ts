// src/handlers/matching-worker.ts
// AR-52: Replaced Redis with DynamoDB session cache
import {
  SQSHandler,
  SQSBatchResponse,
  SQSBatchItemFailure,
  SQSRecord,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  FingerprintPayload,
  generateIdempotencyKey,
} from "../services/matching";
import { DynamoCacheService } from "../services/cache";
// Note: BloomFilter removed per AR-21 - adds complexity without sufficient value
import { getMatchingWorkerEnv, MatchingWorkerEnvConfig } from "../config/env";
import {
  SESSION_TTL_SECONDS,
  TIER2_TIMEOUT_MS,
  MUTATION_GATE_TTL_SECONDS,
} from "../helpers/constants";

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
 * Process a single SQS record
 */
async function processRecord(
  record: SQSRecord,
  service: MatchingService,
): Promise<void> {
  const startTime = Date.now();
  const payload: FingerprintPayload = JSON.parse(record.body);
  const { session_id, tenant_id, fingerprint } = payload;

  logger.info("Processing fingerprint", { session_id, tenant_id });

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
    const matchResponse = await service.runTieredMatching(
      tenant_id,
      fingerprint,
    );
    matchResult = matchResponse.result;
    tier2TimedOut = matchResponse.tier2TimedOut;
    recordTierMetric(matchResult.match_tier, matchResult.is_new_device);

    // Track Tier2 timeouts for monitoring "fail open" scenarios
    if (tier2TimedOut) {
      metrics.addMetric("Tier2Timeout", MetricUnit.Count, 1);
      logger.warn("Tier2 matching timed out", { session_id, tenant_id });
    }
  } catch (error) {
    // On matching failure, write degraded status
    logger.error("Matching failed", { error, session_id });
    await service.writeDegradedResult(session_id, idempotencyKey);
    throw error;
  }

  // Write result to DynamoDB session cache
  await service.writeMatchResult(session_id, matchResult, idempotencyKey);

  // Queue profile update (pass is_new_device for flag computation)
  await service.queueProfileUpdate(
    tenant_id,
    matchResult.device_id,
    payload,
    matchResult.is_new_device,
  );

  const duration = Date.now() - startTime;
  metrics.addMetric("MatchingDuration", MetricUnit.Milliseconds, duration);
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
