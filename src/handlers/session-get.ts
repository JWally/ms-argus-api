// src/handlers/session-get.ts
// AR-67: Lambda handler for retrieving session match results
// AR-96: Refactored to use Middy for automatic metrics publishing
// AR-XXX: V3 response schema with validation

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

// ==================== CONFIGURATION ====================

interface SessionGetEnvConfig {
  SESSION_CACHE_TABLE: string;
  SESSION_PAYLOAD_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["SESSION_CACHE_TABLE", "SESSION_PAYLOAD_TABLE"]);

  return {
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
    SESSION_PAYLOAD_TABLE: process.env.SESSION_PAYLOAD_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME ?? "argus-session-get",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
  };
}

// Validate env at cold start
const envConfig = getEnvConfig();

// Powertools
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
const dynamodb = new DynamoDBClient({});
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: 3600, // Not used for reads
  mutationGateTtlSeconds: 60, // Not used for reads
});

// ==================== CORE HANDLER ====================

const baseHandler = createBaseHandler({
  dynamodb,
  cacheService,
  payloadTable: envConfig.SESSION_PAYLOAD_TABLE,
  logger,
  metrics,
});

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
  .use(jsonErrorHandler({ logger }));
