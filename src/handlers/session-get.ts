import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { boundedRequestHandler } from "../helpers/sdk-http-handler";
import middy from "@middy/core";
import warmup from "@middy/warmup";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { onWarmup } from "../helpers/middy-helpers";
import { createBaseHandler } from "./session-get/base-handler";

interface SessionGetEnvConfig {
  INTEGRITY_RESULTS_TABLE: string;
  MERCHANTS_TABLE_NAME: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["INTEGRITY_RESULTS_TABLE", "MERCHANTS_TABLE_NAME"]);
  return {
    INTEGRITY_RESULTS_TABLE: process.env.INTEGRITY_RESULTS_TABLE as string,
    MERCHANTS_TABLE_NAME: process.env.MERCHANTS_TABLE_NAME as string,
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

// Bounded timeouts: session-get only sees traffic when a merchant asks for a
// verdict, so its keep-alive socket routinely dies across the idle gap (see
// sdk-http-handler.ts) — fail fast and retry instead of a ~7.5s blackhole.
const dynamodb = new DynamoDBClient({ requestHandler: boundedRequestHandler });

const baseHandler = createBaseHandler({
  dynamodb,
  integrityResultsTable: envConfig.INTEGRITY_RESULTS_TABLE,
  merchantsTable: envConfig.MERCHANTS_TABLE_NAME,
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
