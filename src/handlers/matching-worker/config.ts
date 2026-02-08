/**
 * Matching worker service initialization and configuration.
 *
 * Creates the MatchingService instance with all required dependencies
 * and configuration derived from environment variables.
 * @module
 */
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
} from "../../services/matching";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import type { Pool } from "pg";
import { DynamoCacheService } from "../../services/cache";
import { SESSION_TTL_SECONDS, TIER2_TIMEOUT_MS } from "../../helpers/constants";
import type { MatchingWorkerEnvConfig } from "../../config/env";

/**
 * Build matching service configuration from environment config.
 *
 * @param envConfig - Environment configuration
 * @returns Matching service configuration
 */
function getConfig(envConfig: MatchingWorkerEnvConfig): MatchingServiceConfig {
  return {
    tier1IndexTable: envConfig.TIER1_INDEX_TABLE,
    tier2BucketsTable: envConfig.TIER2_BUCKETS_TABLE,
    profilesTable: envConfig.PROFILES_TABLE,
    profileQueueUrl: envConfig.PROFILE_QUEUE_URL,
    sessionTtlSeconds: SESSION_TTL_SECONDS,
    tier2TimeoutMs: TIER2_TIMEOUT_MS,
    // Vector search configuration (optional)
    vectorWorkerArn: envConfig.VECTOR_WORKER_ARN,
    vectorCollection: envConfig.VECTOR_COLLECTION,
  };
}

/**
 * Create a configured MatchingService instance.
 *
 * Factory function that wires up all service dependencies including
 * DynamoDB, SQS, Lambda (for vector search), and cache service
 * with configuration from environment.
 *
 * @param deps - AWS clients, cache service, logger, metrics, and environment config
 * @returns Configured MatchingService instance
 */
export function createMatchingService(deps: {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  lambda?: LambdaClient;
  cacheService: DynamoCacheService;
  envConfig: MatchingWorkerEnvConfig;
  logger?: Logger;
  metrics?: Metrics;
  pgPool?: Pool | null;
}): MatchingService {
  const serviceDeps: MatchingServiceDeps = {
    dynamodb: deps.dynamodb,
    sqs: deps.sqs,
    cache: deps.cacheService,
    config: getConfig(deps.envConfig),
    // Vector search dependencies (optional)
    lambda: deps.lambda,
    logger: deps.logger,
    metrics: deps.metrics,
    // PostgreSQL shadow-mode (optional)
    pgPool: deps.pgPool ?? undefined,
  };
  return new MatchingService(serviceDeps);
}
