import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { SQSClient } from "@aws-sdk/client-sqs";
import { S3Client } from "@aws-sdk/client-s3";
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
import { archivePayload as _archivePayload } from "./ingestion/archive";

validateRequiredEnvVars(["SQS_QUEUE_URL"]);
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL!;

const PAYLOAD_ARCHIVE_BUCKET = process.env.PAYLOAD_ARCHIVE_BUCKET;
const PAYLOAD_ARCHIVE_SAMPLE_RATE = parseFloat(
  process.env.PAYLOAD_ARCHIVE_SAMPLE_RATE ?? "0",
);
const s3 = PAYLOAD_ARCHIVE_BUCKET ? new S3Client({}) : null;

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME ?? "argus-ingestion",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
});
const sqs = new SQSClient({});

export const archivePayload = (sessionId: string, payload: unknown) =>
  _archivePayload(sessionId, payload, {
    s3,
    bucket: PAYLOAD_ARCHIVE_BUCKET,
    sampleRate: PAYLOAD_ARCHIVE_SAMPLE_RATE,
    logger,
    metrics,
  });

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
  headers: "Content-Type, Content-Encoding",
};

const baseHandler = createBaseHandler({
  sqs,
  sqsQueueUrl: SQS_QUEUE_URL,
  s3,
  archiveBucket: PAYLOAD_ARCHIVE_BUCKET,
  archiveSampleRate: PAYLOAD_ARCHIVE_SAMPLE_RATE,
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
  .use(
    validator({
      eventSchema: transpileSchema({
        type: "object",
        properties: {
          parsedBody: payloadJsonSchema,
        },
      }),
    }),
  )
  .use(corsMiddleware(CORS_CONFIG))
  .use(jsonErrorHandler({ logger, exposeErrors: "all" }));
