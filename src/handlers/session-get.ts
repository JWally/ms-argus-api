// src/handlers/session-get.ts
// AR-67: Lambda handler for retrieving session match results
// AR-96: Refactored to use Middy for automatic metrics publishing

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { gunzipSync } from "zlib";
import middy from "@middy/core";
import { DynamoCacheService } from "../services/cache/dynamo-cache";
import { HttpError } from "../helpers/http-error";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";

// ==================== CONFIGURATION ====================

interface SessionGetEnvConfig {
  SESSION_CACHE_TABLE: string;
  SESSION_PAYLOAD_TABLE: string; // AR-XXX: Full payload for gRPC stub
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["SESSION_CACHE_TABLE", "SESSION_PAYLOAD_TABLE"]);

  return {
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
    SESSION_PAYLOAD_TABLE: process.env.SESSION_PAYLOAD_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME ?? "argus-session-get",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
  };
}

// Validate env at cold start
const envConfig = getEnvConfig();

// Powertools
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
const dynamodb = new DynamoDBClient({});
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: 3600, // Not used for reads
  mutationGateTtlSeconds: 60, // Not used for reads
});

// ==================== BASE HANDLER ====================

const baseHandler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  const startTime = Date.now();

  // Handle CORS preflight
  if (event.requestContext.http.method === "OPTIONS") {
    return { statusCode: 204 };
  }

  // Only allow GET
  if (event.requestContext.http.method !== "GET") {
    throw new HttpError(405, "Method not allowed");
  }

  // Extract session_id from path parameter
  const sessionId = event.pathParameters?.session_id;
  if (!sessionId) {
    logger.warn("Missing session_id parameter");
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Missing session_id parameter");
  }

  // Validate session_id format (basic sanitization)
  if (sessionId.length > 128 || !/^[\w-]+$/.test(sessionId)) {
    logger.warn("Invalid session_id format", { session_id: sessionId });
    metrics.addMetric("InvalidSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Invalid session_id format");
  }

  // Look up session in cache
  let session;
  try {
    session = await cacheService.checkSessionCache(sessionId);
  } catch (error) {
    logger.error("Failed to retrieve session", {
      error,
      session_id: sessionId,
    });
    metrics.addMetric("SessionGetFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }

  if (!session) {
    logger.info("Session not found", { session_id: sessionId });
    metrics.addMetric("SessionNotFound", MetricUnit.Count, 1);
    throw new HttpError(404, "Session not found");
  }

  // AR-XXX: Fetch full payload from session payload table (gRPC stub)
  // Payload is stored as gzipped base64 to avoid expensive marshall/unmarshall
  let fullPayload: Record<string, unknown> | undefined;
  try {
    const payloadResult = await dynamodb.send(
      new GetItemCommand({
        TableName: envConfig.SESSION_PAYLOAD_TABLE,
        Key: {
          session_id: { S: sessionId },
        },
      }),
    );
    if (payloadResult.Item?.payload_gzip_b64?.S) {
      // Decompress gzipped payload
      const gzipBuffer = Buffer.from(
        payloadResult.Item.payload_gzip_b64.S,
        "base64",
      );
      const jsonString = gunzipSync(gzipBuffer).toString("utf-8");
      fullPayload = JSON.parse(jsonString);
      metrics.addMetric("SessionPayloadFound", MetricUnit.Count, 1);
    }
  } catch (error) {
    // Log but don't fail - payload is optional enhancement
    logger.warn("Failed to fetch session payload", {
      error,
      session_id: sessionId,
    });
    metrics.addMetric("SessionPayloadFetchError", MetricUnit.Count, 1);
  }

  // Success - return session data
  const duration = Date.now() - startTime;
  logger.info("Session retrieved", {
    session_id: sessionId,
    status: session.status,
    device_id: session.device_id,
    duration_ms: duration,
    has_payload: !!fullPayload,
  });
  metrics.addMetric("SessionRetrieved", MetricUnit.Count, 1);
  metrics.addMetric("SessionGetDuration", MetricUnit.Milliseconds, duration);

  // AR-185: Return v2 format response
  // Build identifiers section
  const identifiers: Record<string, unknown> = {
    session_id: sessionId,
  };
  if (session.device_id) {
    identifiers.device_id = session.device_id;
  }
  // Extract identifiers from payload if available
  if (fullPayload?.fingerprint) {
    const fp = fullPayload.fingerprint as Record<string, unknown>;
    if (fp.evercookie_id) identifiers.evercookie_id = fp.evercookie_id;
    if (fp.public_key) identifiers.public_key = fp.public_key;
    if (fp.sigint_id) identifiers.sigint_id = fp.sigint_id;
  }

  // Build analysis section
  const analysis: Record<string, unknown> = {
    status: session.status,
    confidence: session.confidence,
    match_tier: session.match_tier,
    risk_score: session.risk_score,
    flags: session.flags || [],
    evidence_codes: session.evidence_codes || [],
  };
  // Include optional analysis details
  if (session.anomalies) analysis.anomalies = session.anomalies;
  if (session.simhash_details)
    analysis.simhash_details = session.simhash_details;
  if (session.fuzzy_match_info)
    analysis.fuzzy_match_info = session.fuzzy_match_info;

  // Build v2 response
  const v2Response: Record<string, unknown> = {
    identifiers,
    analysis,
  };

  // Include device and network from payload if available
  if (fullPayload) {
    // If payload is already v2 format
    if (fullPayload.device) {
      v2Response.device = fullPayload.device;
    }
    if (fullPayload.network) {
      v2Response.network = fullPayload.network;
    }
    // If payload is v1 format, include raw fingerprint for now
    if (fullPayload.fingerprint) {
      v2Response.device = { raw: fullPayload.fingerprint };
    }
    if (fullPayload.sigint) {
      v2Response.network = { raw: fullPayload.sigint };
    }
  }

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Argus-Schema-Version": "2.0.0",
    },
    body: JSON.stringify(v2Response),
  };
};

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics)) // AR-96: Auto-publishes metrics on success AND error
  .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
  .use(jsonErrorHandler({ logger })); // AR-166: Shared error handler (must be last)
