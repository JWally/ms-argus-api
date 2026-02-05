/**
 * @fileoverview Profile Updater Lambda Handler.
 *
 * Consumes profile update messages from SQS and persists device profiles
 * and matching indexes to DynamoDB. Implements mutation gating to reduce
 * unnecessary writes for frequently-seen devices.
 *
 * Responsibilities:
 * - Update device profiles with latest fingerprint data
 * - Detect fingerprint drift (significant changes over time)
 * - Compute and update risk flags
 * - Maintain Tier1 (hash) and Tier2 (bucket) indexes
 * - Manage SimHash band entries for fuzzy matching
 *
 * @module handlers/profile-updater
 */

import { SQSHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { SQSClient } from "@aws-sdk/client-sqs";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoCacheService } from "../services/cache";
import { getProfileUpdaterEnv } from "../config/env";
import {
  SESSION_TTL_SECONDS,
  MUTATION_GATE_TTL_SECONDS,
} from "../helpers/constants";
import { createProfileService } from "./profile-updater/config";
import { processRecord } from "./profile-updater/process-record";

const envConfig = getProfileUpdaterEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});

const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

// Optional: SQS client for vector queue
// Only initialized if VECTOR_QUEUE_URL is set
const sqsClient = envConfig.VECTOR_QUEUE_URL ? new SQSClient({}) : null;
const vectorQueueUrl = envConfig.VECTOR_QUEUE_URL;

/**
 * AWS Lambda handler for the profile updater.
 *
 * Triggered by SQS messages queued by the matching worker after successful
 * device matching. Each message contains a device ID, fingerprint, and
 * matching metadata to persist.
 *
 * Processing flow:
 * 1. Check mutation gate (skip if recently updated)
 * 2. Load existing profile (if any)
 * 3. Detect fingerprint drift
 * 4. Compute risk flags
 * 5. Write profile and indexes
 * 6. Set mutation gate
 *
 * Uses partial batch failure reporting for reliable processing.
 *
 * @param event - SQS event containing profile update records
 * @returns SQS batch response with partial failures
 *
 * @see {@link ProfileService} for profile persistence logic
 * @see {@link createProfileService} for service configuration
 */
export const handler: SQSHandler = async (event) => {
  const service = createProfileService({ dynamodb, cacheService, envConfig });
  return processSqsBatch(
    event.Records,
    (record) =>
      processRecord(record, service, {
        logger,
        metrics,
        sqsClient,
        vectorQueueUrl,
      }),
    {
      metrics,
      logger,
      successMetric: "ProfileUpdateSuccess",
      errorMetric: "ProfileUpdateError",
    },
  );
};
