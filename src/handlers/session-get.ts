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
import { primeSessionGet } from "./session-get/prime";

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

// Init-prime — top-level await, so (ESM bundle) container init does not
// complete until this resolves. Provisioned-Concurrency runs init when it
// mints a container, so every PC container is fully warm (pubkey + DDB socket
// + projection JIT) before its first real request, and it re-runs on every
// recycle. Awaited-to-completion = no in-flight request to freeze, the safe
// inverse of fire-and-forget eager init. Bounded + fail-open inside.
//
// ONLY prime on PC init. PC init happens off the request path (when a
// container is minted/recycled), so the prime is free there. An on-demand
// cold start (spillover beyond PC) runs init ON the request path — priming
// there would just add ~0.5-3s to that one request. Those fall back to the
// handler's lazy paths (SWR key fetch, normal DDB). AWS sets this env var to
// "provisioned-concurrency" vs "on-demand".
if (process.env.AWS_LAMBDA_INITIALIZATION_TYPE === "provisioned-concurrency") {
  await primeSessionGet({
    dynamodb,
    integrityResultsTable: envConfig.INTEGRITY_RESULTS_TABLE,
    logger,
    metrics,
    ssmPubkeyPath: process.env.PLATFORM_PUBKEY_SSM_PATH,
  });
}
