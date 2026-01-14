// src/handlers/session-get.ts
// AR-67: Lambda handler for retrieving session match results

import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
  Context,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoCacheService } from "../services/cache/dynamo-cache";

// ==================== CONFIGURATION ====================

interface SessionGetEnvConfig {
  SESSION_CACHE_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getEnvConfig(): SessionGetEnvConfig {
  const required = ["SESSION_CACHE_TABLE"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required env vars: ${missing.join(", ")}`);
  }

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
  "Access-Control-Allow-Headers": "Content-Type, X-Tenant-ID, X-API-Key",
  "Access-Control-Max-Age": "86400",
};

function corsResponse(
  statusCode: number,
  body?: string,
  origin?: string,
): APIGatewayProxyResultV2 {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

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

  // Handle CORS preflight
  if (event.requestContext.http.method === "OPTIONS") {
    return corsResponse(204, undefined, origin);
  }

  // Only allow GET
  if (event.requestContext.http.method !== "GET") {
    return errorResponse(405, "Method not allowed", origin);
  }

  // Extract session_id from path parameter
  const sessionId = event.pathParameters?.session_id;
  if (!sessionId) {
    logger.warn("Missing session_id parameter");
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    return errorResponse(400, "Missing session_id parameter", origin);
  }

  // Validate session_id format (basic sanitization)
  if (sessionId.length > 128 || !/^[\w-]+$/.test(sessionId)) {
    logger.warn("Invalid session_id format", { session_id: sessionId });
    metrics.addMetric("InvalidSessionId", MetricUnit.Count, 1);
    return errorResponse(400, "Invalid session_id format", origin);
  }

  // Look up session in cache
  try {
    const session = await cacheService.checkSessionCache(sessionId);

    if (!session) {
      logger.info("Session not found", { session_id: sessionId });
      metrics.addMetric("SessionNotFound", MetricUnit.Count, 1);
      return errorResponse(404, "Session not found", origin);
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
    metrics.publishStoredMetrics();

    // Return relevant fields (exclude internal fields like idempotency_key)
    return corsResponse(
      200,
      JSON.stringify({
        session_id: sessionId,
        status: session.status,
        device_id: session.device_id,
        confidence: session.confidence,
        match_tier: session.match_tier,
        risk_score: session.risk_score,
        flags: session.flags,
        evidence_codes: session.evidence_codes,
      }),
      origin,
    );
  } catch (error) {
    logger.error("Failed to retrieve session", {
      error,
      session_id: sessionId,
    });
    metrics.addMetric("SessionGetFailed", MetricUnit.Count, 1);
    return errorResponse(503, "Service temporarily unavailable", origin);
  }
}
