/**
 * Bundle entry for the PAT-attestation Lambda.
 *
 * Mirrors the ingestion entry pattern: middy wires logger + header
 * normalization + CORS around the raw baseHandler. Keeps all PAT logic in
 * the pat-attest/ subdirectory so the whole subsystem is deletable as a unit.
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import middy from "@middy/core";
import httpHeaderNormalizer from "@middy/http-header-normalizer";

import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { baseHandler } from "./pat-attest/handler";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME ?? "argus-pat-attest",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
});

const CORS_CONFIG = {
  methods: "GET, OPTIONS",
  headers: "Authorization, Content-Type",
};

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(httpHeaderNormalizer())
  .use(corsMiddleware(CORS_CONFIG))
  .use(jsonErrorHandler({ logger, exposeErrors: "all" }));
