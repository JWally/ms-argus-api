// src/handlers/profile-updater.ts
import { SQSHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
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

// Validate environment variables at module load (cold start)
const envConfig = getProfileUpdaterEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK client (reused across invocations)
const dynamodb = new DynamoDBClient({});

// Create DynamoDB cache service
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

/**
 * Profile Updater Lambda Handler
 * Writes device profiles and indexes to DynamoDB
 * Implements mutation gating to reduce unnecessary writes
 */
export const handler: SQSHandler = async (event) => {
  const service = createProfileService({ dynamodb, cacheService, envConfig });
  return processSqsBatch(
    event.Records,
    (record) => processRecord(record, service, { logger, metrics }),
    {
      metrics,
      logger,
      successMetric: "ProfileUpdateSuccess",
      errorMetric: "ProfileUpdateError",
    },
  );
};
