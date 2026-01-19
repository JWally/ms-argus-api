// src/handlers/session-get.ts
// AR-67: Lambda handler for retrieving session match results
// AR-96: Refactored to use Middy for automatic metrics publishing

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import middy from "@middy/core";
import { DynamoCacheService } from "../services/cache/dynamo-cache";
import { HttpError } from "../helpers/http-error";
import { validateRequiredEnvVars } from "../helpers/env-validation";

// ==================== CONFIGURATION ====================

interface SessionGetEnvConfig {
  SESSION_CACHE_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  validateRequiredEnvVars(["SESSION_CACHE_TABLE"]);

  return {
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
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

// ==================== CORS ====================

const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

// ==================== MIDDLEWARE ====================

/**
 * Adds CORS headers to all responses
 */
const corsHeaders = (): middy.MiddlewareObj<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> => ({
  after: (request) => {
    const origin = request.event.headers["origin"];
    if (!origin) return;

    request.response = request.response ?? { statusCode: 200 };
    const response = request.response as APIGatewayProxyResultV2 & {
      headers?: Record<string, string>;
    };
    response.headers = {
      ...response.headers,
      "Access-Control-Allow-Origin": origin,
      ...CORS_HEADERS,
    };
  },
  onError: (request) => {
    const origin = request.event.headers["origin"];
    if (!origin) return;

    request.response = request.response ?? { statusCode: 500 };
    const response = request.response as APIGatewayProxyResultV2 & {
      headers?: Record<string, string>;
    };
    response.headers = {
      ...response.headers,
      "Access-Control-Allow-Origin": origin,
      ...CORS_HEADERS,
    };
  },
});

/**
 * Custom error handler that returns JSON responses
 */
const jsonErrorHandler = (): middy.MiddlewareObj<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> => ({
  onError: (request) => {
    const error = request.error;
    const statusCode =
      error && typeof error === "object" && "statusCode" in error
        ? (error as { statusCode: number }).statusCode
        : 500;

    const message =
      statusCode < 500 && error instanceof Error
        ? error.message
        : "Service temporarily unavailable";

    logger.warn("Request error", { error, statusCode });

    request.response = {
      statusCode,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: message }),
    };
  },
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

  // Success - return session data
  const duration = Date.now() - startTime;
  logger.info("Session retrieved", {
    session_id: sessionId,
    status: session.status,
    device_id: session.device_id,
    duration_ms: duration,
  });
  metrics.addMetric("SessionRetrieved", MetricUnit.Count, 1);
  metrics.addMetric("SessionGetDuration", MetricUnit.Milliseconds, duration);

  // Return relevant fields (exclude internal fields like idempotency_key)
  // AR-148: Include anomalies if present (server-side anomaly detection results)
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      status: session.status,
      device_id: session.device_id,
      confidence: session.confidence,
      match_tier: session.match_tier,
      risk_score: session.risk_score,
      flags: session.flags,
      evidence_codes: session.evidence_codes,
      anomalies: session.anomalies, // AR-148: Server-side anomaly detection results
    }),
  };
};

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics)) // AR-96: Auto-publishes metrics on success AND error
  .use(corsHeaders()) // Adds CORS headers to responses
  .use(jsonErrorHandler()); // Returns JSON error responses (must be last)
