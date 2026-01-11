// src/handlers/profile-updater.ts
import {
  SQSHandler,
  SQSBatchResponse,
  SQSBatchItemFailure,
  SQSRecord,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
// import { Tracer } from '@aws-lambda-powertools/tracer'; // Disabled due to @smithy bundling issues
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import Redis from "ioredis";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
  ProfileUpdatePayload,
} from "../services/profile";
// Note: BloomFilter removed per AR-21 - adds complexity without sufficient value
import { getProfileUpdaterEnv, ProfileUpdaterEnvConfig } from "../config/env";
import {
  PROFILE_TTL_DAYS,
  MUTATION_GATE_TTL_SECONDS,
  REDIS_RETRY_BASE_MS,
  REDIS_RETRY_MAX_MS,
} from "../helpers/constants";

// Validate environment variables at module load (cold start)
// Throws immediately if required env vars are missing
const envConfig: ProfileUpdaterEnvConfig = getProfileUpdaterEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
// const tracer = new Tracer({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME }); // Disabled
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK client (reused across invocations)
// Note: Tracer capture disabled temporarily due to bundling issues with @smithy
const dynamodb = new DynamoDBClient({});

// Redis client (lazy initialized, reused)
let redis: Redis | null = null;

function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      host: envConfig.REDIS_ENDPOINT,
      port: envConfig.REDIS_PORT,
      tls: {},
      // Lambda-optimized connection settings (AR-20)
      enableReadyCheck: false, // Skip PING on connect (saves ~10ms)
      maxRetriesPerRequest: 2, // Limited retries - Lambda has limited time
      connectTimeout: 5000, // 5s connect timeout
      commandTimeout: 3000, // 3s command timeout
      keepAlive: 30000, // Keep connections alive for Lambda reuse
      retryStrategy: (times: number) => {
        if (times > 3) return null; // Stop retrying after 3 attempts
        return Math.min(
          Math.pow(2, times) * REDIS_RETRY_BASE_MS,
          REDIS_RETRY_MAX_MS,
        );
      },
    });
  }
  return redis;
}

// Service configuration from validated environment
function getConfig(): ProfileServiceConfig {
  return {
    profilesTable: envConfig.PROFILES_TABLE,
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profileTtlDays: PROFILE_TTL_DAYS,
    mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
  };
}

// Create service with production dependencies
function createProfileService(): ProfileService {
  const deps: ProfileServiceDeps = {
    dynamodb,
    redis: getRedis(),
    config: getConfig(),
  };
  return new ProfileService(deps);
}

/**
 * Profile Updater Lambda Handler
 * Writes device profiles and indexes to DynamoDB
 * Implements mutation gating to reduce unnecessary writes
 */
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];
  const service = createProfileService();

  for (const record of event.Records) {
    try {
      await processRecord(record, service);
      metrics.addMetric("ProfileUpdateSuccess", MetricUnit.Count, 1);
    } catch (error) {
      logger.error("Failed to process record", {
        error,
        messageId: record.messageId,
      });
      metrics.addMetric("ProfileUpdateError", MetricUnit.Count, 1);
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
  service: ProfileService,
): Promise<void> {
  const startTime = Date.now();
  const payload: ProfileUpdatePayload = JSON.parse(record.body);
  const { tenant_id, device_id } = payload;

  logger.info("Processing profile update", { tenant_id, device_id });

  const result = await service.processProfileUpdate(payload);

  if (result.skipped) {
    if (result.reason === "mutation_gate") {
      metrics.addMetric("MutationGateSkip", MetricUnit.Count, 1);
      logger.info("Skipping update - recently updated", { device_id });
    } else if (result.reason === "no_drift") {
      metrics.addMetric("NoDriftSkip", MetricUnit.Count, 1);
      logger.info("Skipping update - no significant drift", { device_id });
    }
    return;
  }

  // Record write metrics
  metrics.addMetric("ProfileWrite", MetricUnit.Count, 1);
  metrics.addMetric(
    "Tier1IndexWrites",
    MetricUnit.Count,
    result.tier1Writes ?? 0,
  );
  metrics.addMetric(
    "Tier2BucketWrites",
    MetricUnit.Count,
    result.tier2Writes ?? 0,
  );

  const duration = Date.now() - startTime;
  metrics.addMetric("ProfileUpdateDuration", MetricUnit.Milliseconds, duration);
  logger.info("Profile update complete", {
    tenant_id,
    device_id,
    duration,
    tier1Writes: result.tier1Writes,
    tier2Writes: result.tier2Writes,
  });
}
