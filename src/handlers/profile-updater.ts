// src/handlers/profile-updater.ts
import { SQSHandler, SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
  ProfileUpdatePayload,
} from "../services/profile";
import { DynamoCacheService } from "../services/cache";
import { getProfileUpdaterEnv, ProfileUpdaterEnvConfig } from "../config/env";
import {
  PROFILE_TTL_DAYS,
  TIER2_BUCKET_TTL_DAYS,
  MUTATION_GATE_TTL_SECONDS,
  SESSION_TTL_SECONDS,
} from "../helpers/constants";
import { normalizeFingerprint } from "../helpers/normalize-fingerprint";

// Validate environment variables at module load (cold start)
// Throws immediately if required env vars are missing
const envConfig: ProfileUpdaterEnvConfig = getProfileUpdaterEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK client (reused across invocations)
const dynamodb = new DynamoDBClient({});

// Service configuration from validated environment
function getConfig(): ProfileServiceConfig {
  return {
    profilesTable: envConfig.PROFILES_TABLE,
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profileTtlDays: PROFILE_TTL_DAYS,
    tier2BucketTtlDays: TIER2_BUCKET_TTL_DAYS,
    mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
  };
}

// Create DynamoDB cache service
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

// Create service with production dependencies
function createProfileService(): ProfileService {
  const deps: ProfileServiceDeps = {
    dynamodb,
    cache: cacheService,
    config: getConfig(),
  };
  return new ProfileService(deps);
}

/**
 * Profile Updater Lambda Handler
 * Writes device profiles and indexes to DynamoDB
 * Implements mutation gating to reduce unnecessary writes
 */
export const handler: SQSHandler = async (event) => {
  const service = createProfileService();
  return processSqsBatch(
    event.Records,
    (record) => processRecord(record, service),
    {
      metrics,
      logger,
      successMetric: "ProfileUpdateSuccess",
      errorMetric: "ProfileUpdateError",
    },
  );
};

interface ProfileResult {
  skipped: boolean;
  reason?: string;
  tier1Writes?: number;
  tier2Writes?: number;
}

function recordSkipMetrics(result: ProfileResult, deviceId: string): void {
  if (result.reason === "mutation_gate") {
    metrics.addMetric("MutationGateSkip", MetricUnit.Count, 1);
    logger.info("Skipping update - recently updated", { device_id: deviceId });
  } else if (result.reason === "no_drift") {
    metrics.addMetric("NoDriftSkip", MetricUnit.Count, 1);
    if (result.tier2Writes) {
      metrics.addMetric(
        "Tier2BucketWrites",
        MetricUnit.Count,
        result.tier2Writes,
      );
    }
    logger.info("Skipping update - no significant drift", {
      device_id: deviceId,
      tier2Writes: result.tier2Writes,
    });
  }
}

function recordWriteMetrics(
  result: ProfileResult,
  deviceId: string,
  duration: number,
): void {
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
  metrics.addMetric("ProfileUpdateDuration", MetricUnit.Milliseconds, duration);
  logger.info("Profile update complete", {
    device_id: deviceId,
    duration,
    tier1Writes: result.tier1Writes,
    tier2Writes: result.tier2Writes,
  });
}

async function processRecord(
  record: SQSRecord,
  service: ProfileService,
): Promise<void> {
  const startTime = Date.now();

  // Don't retry malformed JSON - treat as poison message
  let rawPayload: ProfileUpdatePayload;
  try {
    rawPayload = JSON.parse(record.body);
  } catch (parseError) {
    logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200), // Truncate for logging
    });
    metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return; // Don't retry - mark as processed
  }

  const { device_id } = rawPayload;

  // Normalize fingerprint and preserve raw for cross-field anomaly detection
  const payload: ProfileUpdatePayload = {
    ...rawPayload,
    fingerprint: normalizeFingerprint(
      rawPayload.fingerprint,
      rawPayload.sigint,
    ),
    raw_fingerprint: rawPayload.fingerprint,
  };

  logger.info("Processing profile update", { device_id });

  const result = await service.processProfileUpdate(payload);

  if (result.skipped) {
    recordSkipMetrics(result, device_id);
    return;
  }

  recordWriteMetrics(result, device_id, Date.now() - startTime);
}
