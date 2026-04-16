import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { SQSClient } from "@aws-sdk/client-sqs";
import middy from "@middy/core";
import httpHeaderNormalizer from "@middy/http-header-normalizer";
import validator from "@middy/validator";
import { transpileSchema } from "@middy/validator/transpile";
import warmup from "@middy/warmup";
import { onWarmup } from "../helpers/middy-helpers";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { payloadJsonSchema } from "../helpers/payload-schema";
import { binaryGzipBodyParser, jsonBodyParser } from "./ingestion/middleware";
import { createBaseHandler } from "./ingestion/base-handler";

validateRequiredEnvVars(["SQS_QUEUE_URL"]);
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL as string;

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME ?? "argus-ingestion",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
});
const sqs = new SQSClient({});

// Configurable body size limits via env vars for dev data collection
const MAX_BODY_BYTES = parseInt(
  process.env.MAX_BODY_BYTES ?? String(256 * 1024),
  10,
); // 256KB default
const MAX_DECOMPRESSED_BYTES = parseInt(
  process.env.MAX_DECOMPRESSED_BYTES ?? String(2 * 1024 * 1024),
  10,
); // 2MB default

const CORS_CONFIG = {
  methods: "POST, OPTIONS",
  // Mirror the custom headers the argus-integrity bundle sends on POST so
  // preflight approves them. Must stay in sync with bridge.ts request.
  headers:
    "Content-Type, Content-Encoding, X-Argus-Origin, X-Argus-Session, X-Argus-V, X-Argus-Schema-Version",
};

const baseHandler = createBaseHandler({
  sqs,
  sqsQueueUrl: SQS_QUEUE_URL,
  logger,
  metrics,
});

export const handler = middy(baseHandler)
  .use(warmup({ onWarmup }))
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(httpHeaderNormalizer())
  .use(
    binaryGzipBodyParser(
      {
        maxBodyBytes: MAX_BODY_BYTES,
        maxDecompressedBytes: MAX_DECOMPRESSED_BYTES,
      },
      metrics,
    ),
  )
  .use(jsonBodyParser(metrics))
  .use({
    before: async (request) => {
      // Skip payload validation for /v1/integrity-collect — different schema
      if (request.event.rawPath === "/v1/integrity-collect") return;
      const v = validator({
        eventSchema: transpileSchema({
          type: "object",
          properties: {
            parsedBody: payloadJsonSchema,
          },
        }),
      });
      return v.before?.(request);
    },
  })
  .use(corsMiddleware(CORS_CONFIG))
  .use(jsonErrorHandler({ logger, exposeErrors: "all" }));
