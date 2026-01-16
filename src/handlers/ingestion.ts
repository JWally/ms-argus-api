// src/handlers/ingestion.ts
// AR-52: Lambda ingestion handler replacing Go/ECS service
// AR-71: Reverted to async (SQS) for scalability at 30B RPY
// AR-90: Simplified to binary gzip (application/octet-stream)
// AR-XX: Refactored to use middy middleware for cleaner code

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import middy from "@middy/core";
import httpHeaderNormalizer from "@middy/http-header-normalizer";
import warmup from "@middy/warmup";
import { onWarmup } from "../helpers/middy-helpers";
import { gunzipSync } from "zlib";

// Custom HttpError class to replace http-errors module (ESM bundling compatible)
class HttpError extends Error {
  statusCode: number;
  expose: boolean;
  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.expose = statusCode < 500; // Only expose client errors
  }
}
const createError = (statusCode: number, message: string) =>
  new HttpError(statusCode, message);

// ==================== CONFIGURATION ====================

const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL;
if (!SQS_QUEUE_URL) throw new Error("Missing required env var: SQS_QUEUE_URL");

const API_KEYS: Record<string, string> = process.env.API_KEYS
  ? JSON.parse(process.env.API_KEYS)
  : {};

// AR-124: Stage for tenant isolation guard
const STAGE = process.env.STAGE ?? "";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME ?? "argus-ingestion",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
});
const sqs = new SQSClient({});

const MAX_BODY_BYTES = 64 * 1024; // 64KB
const MAX_DECOMPRESSED_BYTES = 512 * 1024; // 512KB (zip bomb defense)

// CORS headers (reflect origin for backward compatibility)
const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Content-Encoding, X-Tenant-ID, X-API-Key",
  "Access-Control-Max-Age": "86400",
};

// ==================== CUSTOM MIDDLEWARE ====================

/**
 * Handles binary gzip decompression (AR-90)
 * Validates isBase64Encoded flag and enforces byte limits
 */
const binaryGzipBodyParser =
  (): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
    before: (request) => {
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

      // Decompress with size limit (zip bomb defense)
      try {
        const decompressed = gunzipSync(gzipBuffer);
        if (decompressed.length > MAX_DECOMPRESSED_BYTES) {
          throw createError(400, "Decompressed payload too large");
        }
        event.body = decompressed.toString("utf-8");
        metrics.addMetric("BinaryGzipPayloadReceived", MetricUnit.Count, 1);
      } catch (err) {
        if (err instanceof HttpError) throw err;
        metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
        throw createError(400, "Failed to decompress gzip payload");
      }
    },
  });

/**
 * Custom error handler that returns JSON responses with CORS headers
 */
const jsonErrorHandler = (): middy.MiddlewareObj<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> => ({
  onError: (request) => {
    const { error, event } = request;
    const origin = event.headers?.["origin"];

    // Get status code from http-errors or default to 500
    const statusCode =
      error && typeof error === "object" && "statusCode" in error
        ? (error as { statusCode: number }).statusCode
        : 500;

    const message =
      error instanceof Error ? error.message : "Internal server error";

    logger.warn("Request error", { error, statusCode });

    // Build response with CORS headers
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (origin) {
      headers["Access-Control-Allow-Origin"] = origin;
      Object.assign(headers, CORS_HEADERS);
    }

    request.response = {
      statusCode,
      headers,
      body: JSON.stringify({ error: message }),
    };
  },
});

/**
 * Adds CORS headers to successful responses
 */
const corsHeaders = (): middy.MiddlewareObj<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> => ({
  after: (request) => {
    const origin = request.event.headers?.["origin"];
    if (!origin || !request.response) return;

    const response = request.response as APIGatewayProxyResultV2 & {
      headers?: Record<string, string>;
    };
    response.headers = response.headers ?? {};
    response.headers["Access-Control-Allow-Origin"] = origin;
    Object.assign(response.headers, CORS_HEADERS);
  },
});

// ==================== CORE HANDLER ====================

const baseHandler = async (
  event: APIGatewayProxyEventV2,
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

  // Parse JSON (body already decompressed by middleware if binary)
  let payload: { session_id?: string; fingerprint?: unknown; sigint?: unknown };
  try {
    payload = JSON.parse(event.body ?? "{}");
  } catch {
    metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
    throw createError(400, "Invalid JSON payload");
  }

  // Validate required fields
  if (!payload.session_id || typeof payload.session_id !== "string") {
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    throw createError(400, "Missing required field: session_id");
  }

  // Tenant extraction from API key or header
  let tenantId: string;
  const apiKey = event.headers["x-api-key"];
  if (Object.keys(API_KEYS).length > 0 && apiKey) {
    tenantId = API_KEYS[apiKey];
    if (!tenantId) {
      metrics.addMetric("AuthFailed", MetricUnit.Count, 1);
      throw createError(401, "Invalid API key");
    }
  } else {
    // AR-124: In production, require API key configuration - no silent fallback
    const headerTenantId = event.headers["x-tenant-id"];
    if (STAGE === "prod" && !headerTenantId) {
      metrics.addMetric("TenantIsolationViolation", MetricUnit.Count, 1);
      logger.error("Missing tenant ID in production", {
        hasApiKeyConfig: Object.keys(API_KEYS).length > 0,
        hasApiKeyHeader: !!apiKey,
        hasTenantIdHeader: !!headerTenantId,
      });
      throw createError(
        500,
        "Tenant configuration error - contact support. Missing tenant identification in production environment.",
      );
    }
    tenantId = headerTenantId ?? "default";
  }

  // Build SQS message payload
  const sqsPayload = {
    session_id: payload.session_id,
    tenant_id: tenantId,
    fingerprint: payload.fingerprint,
    sigint: payload.sigint,
    headers: {
      "User-Agent": event.headers["user-agent"],
      "Accept-Language": event.headers["accept-language"],
      "X-Forwarded-For": event.headers["x-forwarded-for"],
    },
    timestamp: Date.now(),
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
      session_id: payload.session_id,
    });
    metrics.addMetric("SqsSendFailed", MetricUnit.Count, 1);
    throw createError(503, "Service temporarily unavailable");
  }

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
  .use(corsHeaders()) // Adds CORS headers to responses
  .use(jsonErrorHandler()); // Returns JSON error responses (must be last)
