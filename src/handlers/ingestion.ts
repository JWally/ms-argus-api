// src/handlers/ingestion.ts
// AR-52: Lambda ingestion handler replacing Go/ECS service
// AR-71: Reverted to async (SQS) for scalability at 30B RPY
// AR-87: Added gzip decompression support for large fingerprint payloads
// Receives fingerprints via HTTP API, validates, and queues to SQS

import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
  Context,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { gunzipSync } from "zlib";

// ==================== CONFIGURATION ====================

interface IngestionEnvConfig {
  SQS_QUEUE_URL: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
  API_KEYS?: string; // JSON: {"key": "tenant-id"}
}

function getIngestionEnv(): IngestionEnvConfig {
  const required = ["SQS_QUEUE_URL"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required env vars: ${missing.join(", ")}`);
  }

  return {
    SQS_QUEUE_URL: process.env.SQS_QUEUE_URL!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME ?? "argus-ingestion",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
    API_KEYS: process.env.API_KEYS,
  };
}

// Validate env at cold start
const envConfig = getIngestionEnv();

// Parse API keys if provided
const apiKeyTenants: Map<string, string> = new Map();
if (envConfig.API_KEYS) {
  try {
    const parsed = JSON.parse(envConfig.API_KEYS);
    for (const [key, tenant] of Object.entries(parsed)) {
      apiKeyTenants.set(key, tenant as string);
    }
  } catch {
    // Invalid JSON - ignore API key validation
  }
}

// Powertools
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
const sqs = new SQSClient({});

// ==================== CONSTANTS ====================

const MAX_BODY_SIZE = 64 * 1024; // 64KB for uncompressed payloads
const MAX_GZIP_BODY_SIZE = 64 * 1024; // 64KB for compressed payload (raw)
const MAX_DECOMPRESSED_SIZE = 512 * 1024; // 512KB max after decompression (zip bomb defense)
const MAX_JSON_DEPTH = 10;

// CORS headers
const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Tenant-ID, X-API-Key",
  "Access-Control-Max-Age": "86400",
};

// ==================== TYPES ====================

interface FingerprintPayload {
  session_id: string;
  tenant_id: string;
  fingerprint?: unknown;
  /** AR-81: Sigint data from ms-argus-web */
  sigint?: unknown;
  tcp_blob?: string;
  tls_blob?: string;
  headers: Record<string, string>;
  timestamp: number;
}

// ==================== VALIDATION ====================

/**
 * Calculate JSON nesting depth to prevent DoS via deeply nested payloads
 */
function getJsonDepth(json: string): number {
  let depth = 0;
  let maxDepth = 0;
  let inString = false;
  let escape = false;

  for (const char of json) {
    if (escape) {
      escape = false;
      continue;
    }
    if (char === "\\") {
      escape = true;
      continue;
    }
    if (char === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;

    if (char === "{" || char === "[") {
      depth++;
      maxDepth = Math.max(maxDepth, depth);
    } else if (char === "}" || char === "]") {
      depth--;
    }
  }

  return maxDepth;
}

/**
 * Extract tenant ID from request
 * - If API_KEYS configured: validate X-API-Key header
 * - Otherwise: use X-Tenant-ID header or default
 */
function extractTenant(
  event: APIGatewayProxyEventV2,
): { tenant: string } | { error: string; status: number } {
  const apiKey = event.headers["x-api-key"];
  const tenantHeader = event.headers["x-tenant-id"];

  if (apiKeyTenants.size > 0) {
    // Multi-tenant mode with API key validation
    if (!apiKey) {
      return { tenant: "default" }; // Backward compatible
    }
    const tenant = apiKeyTenants.get(apiKey);
    if (!tenant) {
      return { error: "Invalid API key", status: 401 };
    }
    return { tenant };
  }

  // Single-tenant mode
  return { tenant: tenantHeader ?? "default" };
}

/**
 * Extract relevant headers from request
 */
function extractHeaders(event: APIGatewayProxyEventV2): Record<string, string> {
  const headers: Record<string, string> = {};
  const relevantHeaders = ["user-agent", "accept-language", "x-forwarded-for"];

  for (const header of relevantHeaders) {
    const value = event.headers[header];
    if (value) {
      // Normalize header name to match Go service format
      const normalizedName = header
        .split("-")
        .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
        .join("-");
      headers[normalizedName] = value;
    }
  }

  return headers;
}

/**
 * AR-87: Decompress gzip payload
 * Returns decompressed string or error object
 *
 * Handles two cases:
 * 1. API Gateway binary mode: isBase64Encoded=true, body is double-encoded
 *    (API GW base64-encodes the base64 text we sent)
 * 2. Browser sends base64 text: isBase64Encoded=false, body is our base64 gzip
 */
function decompressGzipPayload(
  body: string,
  isBase64Encoded: boolean,
): { data: string } | { error: string } {
  try {
    let gzipBase64: string;

    if (isBase64Encoded) {
      // API Gateway base64-encoded our base64 text, so decode once to get our original base64
      gzipBase64 = Buffer.from(body, "base64").toString("utf-8");
    } else {
      // Body is our base64 text directly
      gzipBase64 = body;
    }

    // Now decode our base64 to get the gzip bytes
    const gzipBuffer = Buffer.from(gzipBase64, "base64");

    // Validate it looks like gzip (magic bytes: 1f 8b)
    if (
      gzipBuffer.length < 2 ||
      gzipBuffer[0] !== 0x1f ||
      gzipBuffer[1] !== 0x8b
    ) {
      return { error: "Invalid gzip data" };
    }

    const decompressed = gunzipSync(gzipBuffer);

    // Check decompressed size (zip bomb defense)
    if (decompressed.length > MAX_DECOMPRESSED_SIZE) {
      return { error: "Decompressed payload too large" };
    }

    return { data: decompressed.toString("utf-8") };
  } catch {
    return { error: "Failed to decompress gzip payload" };
  }
}

// ==================== RESPONSES ====================

function corsResponse(
  statusCode: number,
  body?: string,
  origin?: string,
): APIGatewayProxyResultV2 {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Reflect origin for CORS
  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    Object.assign(headers, CORS_HEADERS);
  }

  return {
    statusCode,
    headers,
    body: body ?? "",
  };
}

function errorResponse(
  status: number,
  message: string,
  origin?: string,
): APIGatewayProxyResultV2 {
  return corsResponse(status, JSON.stringify({ error: message }), origin);
}

// ==================== HANDLER ====================

export async function handler(
  event: APIGatewayProxyEventV2,
  _context: Context,
): Promise<APIGatewayProxyResultV2> {
  const startTime = Date.now();
  const origin = event.headers["origin"];

  // Health check endpoint
  if (event.rawPath === "/health") {
    return corsResponse(200, JSON.stringify({ status: "healthy" }), origin);
  }

  // Handle CORS preflight
  if (event.requestContext.http.method === "OPTIONS") {
    return corsResponse(204, undefined, origin);
  }

  // Only allow POST to /v1/collect
  if (event.requestContext.http.method !== "POST") {
    return errorResponse(405, "Method not allowed", origin);
  }

  if (event.rawPath !== "/v1/collect") {
    return errorResponse(404, "Not found", origin);
  }

  // AR-87: Check for gzip encoding (case-insensitive)
  const contentEncoding = event.headers["content-encoding"]?.toLowerCase();
  const isGzipped = contentEncoding === "gzip";

  // Validate body size (different limits for compressed vs uncompressed)
  const rawBody = event.body ?? "";
  const maxSize = isGzipped ? MAX_GZIP_BODY_SIZE : MAX_BODY_SIZE;
  if (rawBody.length > maxSize) {
    logger.warn("Payload too large", { size: rawBody.length, isGzipped });
    metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
    return errorResponse(413, "Request entity too large", origin);
  }

  // AR-87: Decompress if gzipped
  let body: string;
  if (isGzipped) {
    // Debug: log what we received
    logger.info("Gzip request received", {
      bodyLength: rawBody.length,
      bodyStart: rawBody.substring(0, 50),
      isBase64Encoded: event.isBase64Encoded,
    });

    const decompressResult = decompressGzipPayload(
      rawBody,
      event.isBase64Encoded,
    );
    if ("error" in decompressResult) {
      logger.warn("Gzip decompression failed", {
        error: decompressResult.error,
        bodyStart: rawBody.substring(0, 100),
      });
      metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
      return errorResponse(400, decompressResult.error, origin);
    }
    body = decompressResult.data;
    metrics.addMetric("GzipPayloadReceived", MetricUnit.Count, 1);
  } else {
    body = rawBody;
  }

  // Parse JSON
  let payload: { session_id?: string; fingerprint?: unknown; sigint?: unknown };
  try {
    payload = JSON.parse(body);
  } catch {
    logger.warn("Invalid JSON payload");
    metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
    return errorResponse(400, "Invalid JSON payload", origin);
  }

  // Validate required fields
  if (!payload.session_id || typeof payload.session_id !== "string") {
    logger.warn("Missing session_id");
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    return errorResponse(400, "Missing required field: session_id", origin);
  }

  // Check JSON depth (DoS prevention)
  if (payload.fingerprint) {
    const fingerprintJson = JSON.stringify(payload.fingerprint);
    const depth = getJsonDepth(fingerprintJson);
    if (depth > MAX_JSON_DEPTH) {
      logger.warn("Fingerprint JSON too deeply nested", { depth });
      metrics.addMetric("JsonTooDeep", MetricUnit.Count, 1);
      return errorResponse(400, "Fingerprint JSON too deeply nested", origin);
    }
  }

  // Extract tenant
  const tenantResult = extractTenant(event);
  if ("error" in tenantResult) {
    logger.warn("Authentication failed");
    metrics.addMetric("AuthFailed", MetricUnit.Count, 1);
    return errorResponse(tenantResult.status, tenantResult.error, origin);
  }

  // Build SQS message payload
  const sqsPayload: FingerprintPayload = {
    session_id: payload.session_id,
    tenant_id: tenantResult.tenant,
    fingerprint: payload.fingerprint,
    sigint: payload.sigint, // AR-81: Pass sigint data from ms-argus-web
    headers: extractHeaders(event),
    timestamp: Date.now(),
  };

  // Send to SQS
  try {
    await sqs.send(
      new SendMessageCommand({
        QueueUrl: envConfig.SQS_QUEUE_URL,
        MessageBody: JSON.stringify(sqsPayload),
      }),
    );
  } catch (error) {
    logger.error("Failed to send to SQS", {
      error,
      session_id: payload.session_id,
    });
    metrics.addMetric("SqsSendFailed", MetricUnit.Count, 1);
    return errorResponse(503, "Service temporarily unavailable", origin);
  }

  // Success
  const duration = Date.now() - startTime;
  logger.info("Request queued", {
    session_id: payload.session_id,
    tenant_id: tenantResult.tenant,
    duration_ms: duration,
  });
  metrics.addMetric("RequestQueued", MetricUnit.Count, 1);
  metrics.addMetric("IngestionDuration", MetricUnit.Milliseconds, duration);
  metrics.publishStoredMetrics();

  return corsResponse(204, undefined, origin);
}
