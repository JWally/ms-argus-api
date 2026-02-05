import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import middy from "@middy/core";
import { DynamoCacheService } from "../services/cache/dynamo-cache";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { createBaseHandler } from "./session-get/base-handler";

/**
 * Environment configuration for session-get handler
 */
interface SessionGetEnvConfig {
  /** DynamoDB table for session cache */
  SESSION_CACHE_TABLE: string;
  /** DynamoDB table for session payloads */
  SESSION_PAYLOAD_TABLE: string;
  /** DynamoDB table for vector results (optional) */
  VECTOR_RESULTS_TABLE?: string;
  /** Powertools service name */
  POWERTOOLS_SERVICE_NAME: string;
  /** Powertools metrics namespace */
  POWERTOOLS_METRICS_NAMESPACE: string;
}

/**
 * Get and validate environment configuration
 * @returns Validated environment configuration
 */
function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["SESSION_CACHE_TABLE", "SESSION_PAYLOAD_TABLE"]);

  return {
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
    SESSION_PAYLOAD_TABLE: process.env.SESSION_PAYLOAD_TABLE!,
    VECTOR_RESULTS_TABLE: process.env.VECTOR_RESULTS_TABLE,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME ?? "argus-session-get",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
  };
}

const envConfig = getEnvConfig();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: 3600, // Not used for reads
  mutationGateTtlSeconds: 60, // Not used for reads
});

const baseHandler = createBaseHandler({
  dynamodb,
  cacheService,
  payloadTable: envConfig.SESSION_PAYLOAD_TABLE,
  vectorResultsTable: envConfig.VECTOR_RESULTS_TABLE,
  logger,
  metrics,
});

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
  .use(jsonErrorHandler({ logger }));
