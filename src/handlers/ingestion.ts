// src/handlers/ingestion.ts
// AR-52: Lambda ingestion handler replacing Go/ECS service
// AR-71: Reverted to async (SQS) for scalability at 30B RPY
// AR-90: Simplified to binary gzip (application/octet-stream)
// AR-96: Refactored to use middy middleware for cleaner code
// AR-131: API keys from Secrets Manager instead of env var
// AR-XXX: V3 payload schema with middy validator

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

// ==================== CONFIGURATION ====================

validateRequiredEnvVars(["SQS_QUEUE_URL"]);
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL!;

// AR-139: Payload archiving configuration
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

// AR-149: Configurable body size limits via env vars for dev data collection
const MAX_BODY_BYTES = parseInt(
  process.env.MAX_BODY_BYTES ?? String(256 * 1024),
  10,
); // 256KB default (was 64KB)
const MAX_DECOMPRESSED_BYTES = parseInt(
  process.env.MAX_DECOMPRESSED_BYTES ?? String(2 * 1024 * 1024),
  10,
); // 2MB default (was 512KB)

// AR-164: CORS configuration for this handler
const CORS_CONFIG = {
  methods: "POST, OPTIONS",
  headers: "Content-Type, Content-Encoding",
};

// ==================== CORE HANDLER ====================

const baseHandler = createBaseHandler({
  sqs,
  sqsQueueUrl: SQS_QUEUE_URL,
  s3,
  archiveBucket: PAYLOAD_ARCHIVE_BUCKET,
  archiveSampleRate: PAYLOAD_ARCHIVE_SAMPLE_RATE,
  logger,
  metrics,
});

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(warmup({ onWarmup })) // AR-127: Short-circuit warmup events first
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics)) // Auto-publishes metrics on success AND error
  .use(httpHeaderNormalizer()) // Normalizes header casing
  .use(
    binaryGzipBodyParser(
      {
        maxBodyBytes: MAX_BODY_BYTES,
        maxDecompressedBytes: MAX_DECOMPRESSED_BYTES,
      },
      metrics,
    ),
  )
  .use(jsonBodyParser(metrics)) // Parse JSON body
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
  .use(corsMiddleware(CORS_CONFIG)) // AR-164: Shared CORS middleware
  .use(jsonErrorHandler({ logger, exposeErrors: "all" })); // AR-166: Shared error handler (must be last)
