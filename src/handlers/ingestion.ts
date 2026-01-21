// src/handlers/ingestion.ts
// AR-52: Lambda ingestion handler replacing Go/ECS service
// AR-71: Reverted to async (SQS) for scalability at 30B RPY
// AR-90: Simplified to binary gzip (application/octet-stream)
// AR-96: Refactored to use middy middleware for cleaner code
// AR-131: API keys from Secrets Manager instead of env var
// AR-XXX: V3 payload schema with middy validator

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { gzipSync } from "zlib";
import middy from "@middy/core";
import httpHeaderNormalizer from "@middy/http-header-normalizer";
import validator from "@middy/validator";
import { transpileSchema } from "@middy/validator/transpile";
import warmup from "@middy/warmup";
import { onWarmup } from "../helpers/middy-helpers";
import { HttpError, createError } from "../helpers/http-error";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import { createGunzip } from "zlib";
import { pipeline } from "stream/promises";
import { Readable } from "stream";
import {
  payloadJsonSchema,
  getSessionId,
  type ArgusPayload,
} from "../helpers/payload-schema";

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

// ==================== AR-139: PAYLOAD ARCHIVING ====================

/**
 * Archive raw payload to S3 with Hive-style partitioning.
 * Fire-and-forget: errors are logged but do not fail the request.
 * Key format: year=YYYY/month=MM/day=DD/hour=HH/{sessionId}.json.gz
 */
export const archivePayload = async (
  sessionId: string,
  payload: unknown,
): Promise<void> => {
  // Check if archiving is enabled and sample rate check
  if (!s3 || !PAYLOAD_ARCHIVE_BUCKET || PAYLOAD_ARCHIVE_SAMPLE_RATE <= 0) {
    return;
  }

  // Sample rate check (0.0 = never, 1.0 = always)
  if (Math.random() > PAYLOAD_ARCHIVE_SAMPLE_RATE) {
    return;
  }

  try {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    const hour = String(now.getUTCHours()).padStart(2, "0");

    const key = `year=${year}/month=${month}/day=${day}/hour=${hour}/${sessionId}.json.gz`;
    const body = gzipSync(Buffer.from(JSON.stringify(payload)));

    await s3.send(
      new PutObjectCommand({
        Bucket: PAYLOAD_ARCHIVE_BUCKET,
        Key: key,
        Body: body,
        ContentType: "application/json",
        ContentEncoding: "gzip",
      }),
    );

    metrics.addMetric("PayloadArchived", MetricUnit.Count, 1);
  } catch (err) {
    // Log error but don't fail the request (fire-and-forget)
    logger.warn("Payload archive failed", {
      error: err,
      session_id: sessionId,
    });
    metrics.addMetric("PayloadArchiveFailed", MetricUnit.Count, 1);
  }
};

// ==================== CUSTOM MIDDLEWARE ====================

/**
 * Streaming gunzip with early abort when size threshold exceeded.
 * AR-136: Prevents ZIP bomb attacks by aborting before allocating full buffer.
 */
const streamingGunzip = async (
  gzipBuffer: Buffer,
  maxBytes: number,
): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  const gunzip = createGunzip();

  // Track bytes and abort early if threshold exceeded
  gunzip.on("data", (chunk: Buffer) => {
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      gunzip.destroy(
        new Error(
          `Decompressed size exceeds limit (${maxBytes} bytes) - aborting`,
        ),
      );
      return;
    }
    chunks.push(chunk);
  });

  try {
    await pipeline(Readable.from(gzipBuffer), gunzip);
    return Buffer.concat(chunks);
  } catch (err) {
    // Re-throw our size limit error with clear message
    if (err instanceof Error && err.message.includes("exceeds limit")) {
      throw err;
    }
    // Other decompression errors
    throw new Error("Failed to decompress gzip payload");
  }
};

/**
 * Handles binary gzip decompression (AR-90)
 * AR-136: Uses streaming decompression to abort early on ZIP bombs
 * Validates isBase64Encoded flag and enforces byte limits
 */
const binaryGzipBodyParser =
  (): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
    before: async (request) => {
      const { event } = request;
      const contentType = (event.headers["content-type"] ?? "").toLowerCase();
      const contentEncoding = (
        event.headers["content-encoding"] ?? ""
      ).toLowerCase();
      const rawBody = event.body ?? "";

      // Non-binary path: validate size in bytes (not string length)
      if (!contentType.startsWith("application/octet-stream")) {
        if (Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
          metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
          throw createError(413, "Request entity too large");
        }
        // AR-171: Track JSON payload format for adoption monitoring
        metrics.addMetric("JsonPayloadReceived", MetricUnit.Count, 1);
        return;
      }

      // Binary path: require gzip encoding
      if (!contentEncoding.includes("gzip")) {
        metrics.addMetric("MissingGzipEncoding", MetricUnit.Count, 1);
        throw createError(
          400,
          "Binary payload requires Content-Encoding: gzip",
        );
      }

      // Validate isBase64Encoded flag (API Gateway sets this for binary)
      if (!event.isBase64Encoded) {
        throw createError(
          400,
          "Binary payload must be base64-encoded by API Gateway",
        );
      }

      // Decode base64 and validate actual compressed byte size
      const gzipBuffer = Buffer.from(rawBody, "base64");
      if (gzipBuffer.length > MAX_BODY_BYTES) {
        metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
        throw createError(413, "Compressed payload too large");
      }

      // Validate gzip magic bytes (0x1f 0x8b)
      if (
        gzipBuffer.length < 2 ||
        gzipBuffer[0] !== 0x1f ||
        gzipBuffer[1] !== 0x8b
      ) {
        metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
        throw createError(400, "Invalid gzip data");
      }

      // AR-136: Streaming decompress with early abort (zip bomb defense)
      try {
        const decompressed = await streamingGunzip(
          gzipBuffer,
          MAX_DECOMPRESSED_BYTES,
        );
        event.body = decompressed.toString("utf-8");
        metrics.addMetric("BinaryGzipPayloadReceived", MetricUnit.Count, 1);
      } catch (err) {
        if (err instanceof HttpError) throw err;
        metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
        // Preserve error message for size limit errors (AC2)
        const message =
          err instanceof Error && err.message.includes("exceeds limit")
            ? err.message
            : "Failed to decompress gzip payload";
        throw createError(400, message);
      }
    },
  });

/**
 * JSON body parser middleware that parses JSON and attaches to event.body
 * Runs after gzip decompression
 */
const jsonBodyParser = (): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const method = event.requestContext.http.method;

    // Skip for non-POST requests (OPTIONS, GET, etc. don't have bodies to parse)
    if (method !== "POST") {
      return;
    }

    // Skip for non-collect endpoints
    if (event.rawPath !== "/v1/collect") {
      return;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (event as any).parsedBody = JSON.parse(event.body ?? "{}");
    } catch {
      metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
      throw createError(400, "Invalid JSON payload");
    }
  },
});

// ==================== CORE HANDLER ====================

// Extend the event type to include parsedBody
interface ExtendedEvent extends APIGatewayProxyEventV2 {
  parsedBody?: ArgusPayload;
}

const baseHandler = async (
  event: ExtendedEvent,
): Promise<APIGatewayProxyResultV2> => {
  const start = Date.now();

  // Health check endpoint
  if (event.rawPath === "/health") {
    return { statusCode: 200, body: JSON.stringify({ status: "healthy" }) };
  }

  // Routing
  const method = event.requestContext.http.method;
  if (method === "OPTIONS") {
    return { statusCode: 204 };
  }
  if (method !== "POST") {
    throw createError(405, "Method not allowed");
  }
  if (event.rawPath !== "/v1/collect") {
    throw createError(404, "Not found");
  }

  // Payload is parsed and validated by middleware at this point
  const payload = event.parsedBody as ArgusPayload;
  const sessionId = getSessionId(payload);

  // Build SQS message payload - pass through the entire payload with metadata
  const sqsPayload = {
    ...payload,
    // Include headers and metadata
    _headers: {
      "User-Agent": event.headers["user-agent"],
      "Accept-Language": event.headers["accept-language"],
      "X-Forwarded-For": event.headers["x-forwarded-for"],
    },
    _timestamp: Date.now(),
  };

  // Send to SQS
  try {
    await sqs.send(
      new SendMessageCommand({
        QueueUrl: SQS_QUEUE_URL,
        MessageBody: JSON.stringify(sqsPayload),
      }),
    );
  } catch (err) {
    logger.error("SQS send failed", {
      error: err,
      session_id: sessionId,
    });
    metrics.addMetric("SqsSendFailed", MetricUnit.Count, 1);
    throw createError(503, "Service temporarily unavailable");
  }

  // AR-139: Archive raw payload (async fire-and-forget, does not block response)
  archivePayload(sessionId, payload).catch(() => {
    // Error already logged in archivePayload
  });

  // Success metrics
  metrics.addMetric("RequestQueued", MetricUnit.Count, 1);
  metrics.addMetric(
    "IngestionDuration",
    MetricUnit.Milliseconds,
    Date.now() - start,
  );

  return { statusCode: 204 };
};

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(warmup({ onWarmup })) // AR-127: Short-circuit warmup events first
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics)) // Auto-publishes metrics on success AND error
  .use(httpHeaderNormalizer()) // Normalizes header casing
  .use(binaryGzipBodyParser()) // Handles gzip decompression
  .use(jsonBodyParser()) // Parse JSON body
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
