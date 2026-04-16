import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import middy from "@middy/core";
import warmup from "@middy/warmup";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { onWarmup } from "../helpers/middy-helpers";
import { createBaseHandler } from "./session-get/base-handler";

interface SessionGetEnvConfig {
  INTEGRITY_RESULTS_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["INTEGRITY_RESULTS_TABLE"]);
  return {
    INTEGRITY_RESULTS_TABLE: process.env.INTEGRITY_RESULTS_TABLE as string,
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

const baseHandler = createBaseHandler({
  dynamodb,
  integrityResultsTable: envConfig.INTEGRITY_RESULTS_TABLE,
  logger,
  metrics,
});

export const handler = middy(baseHandler)
  .use(warmup({ onWarmup }))
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(
    corsMiddleware({
      methods: "GET, OPTIONS",
      headers: "Content-Type, X-Api-Key",
    }),
  )
  .use(jsonErrorHandler({ logger }));
