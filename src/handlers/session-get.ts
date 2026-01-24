// src/handlers/session-get.ts
// AR-67: Lambda handler for retrieving session match results
// AR-96: Refactored to use Middy for automatic metrics publishing
// AR-XXX: V3 response schema with validation

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
import {
  validateSessionResponse,
  type SessionResponse,
} from "../helpers/payload-schema";

// ==================== CONFIGURATION ====================

interface SessionGetEnvConfig {
  SESSION_CACHE_TABLE: string;
  SESSION_PAYLOAD_TABLE: string;
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

// ==================== HELPERS ====================

function extractSessionId(event: APIGatewayProxyEventV2): string {
  if (event.requestContext.http.method === "OPTIONS") {
    throw Object.assign(new HttpError(0, ""), { preflight: true });
  }
  if (event.requestContext.http.method !== "GET") {
    throw new HttpError(405, "Method not allowed");
  }
  const sessionId = event.pathParameters?.session_id;
  if (!sessionId) {
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Missing session_id parameter");
  }
  if (sessionId.length > 128 || !/^[\w-]+$/.test(sessionId)) {
    metrics.addMetric("InvalidSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Invalid session_id format");
  }
  return sessionId;
}

async function lookupSession(sessionId: string) {
  try {
    const session = await cacheService.checkSessionCache(sessionId);
    if (!session) {
      metrics.addMetric("SessionNotFound", MetricUnit.Count, 1);
      throw new HttpError(404, "Session not found");
    }
    return session;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    logger.error("Failed to retrieve session", {
      error,
      session_id: sessionId,
    });
    metrics.addMetric("SessionGetFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }
}

async function fetchPayload(
  sessionId: string,
): Promise<SessionResponse | undefined> {
  try {
    const result = await dynamodb.send(
      new GetItemCommand({
        TableName: envConfig.SESSION_PAYLOAD_TABLE,
        Key: { session_id: { S: sessionId } },
      }),
    );
    if (!result.Item?.payload_gzip_b64?.S) return undefined;
    const gzipBuffer = Buffer.from(result.Item.payload_gzip_b64.S, "base64");
    const parsed = JSON.parse(gunzipSync(gzipBuffer).toString("utf-8"));
    const validated = validateSessionResponse(parsed);
    metrics.addMetric("SessionPayloadFound", MetricUnit.Count, 1);
    return validated;
  } catch (error) {
    logger.warn("Failed to fetch/validate session payload", {
      error,
      session_id: sessionId,
    });
    metrics.addMetric("SessionPayloadFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildFallbackResponse(
  session: any,
  sessionId: string,
): APIGatewayProxyResultV2 {
  metrics.addMetric("SessionPayloadMissing", MetricUnit.Count, 1);
  const body = JSON.stringify({
    identifiers: {
      session_id: sessionId,
      device_id: session.device_id || "unknown",
    },
    analysis: {
      status: session.status,
      confidence: session.confidence ?? 0,
      match_tier: session.match_tier ?? -1,
      is_new_device: false,
      risk_score: session.risk_score ?? 0,
      flags: session.flags || [],
      evidence_codes: session.evidence_codes || [],
    },
    hashes: { stable: "unavailable", fuzzy: "unavailable" },
    device: {},
  });
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json", "X-Argus-Degraded": "true" },
    body,
  };
}

// ==================== BASE HANDLER ====================

const baseHandler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  const startTime = Date.now();
  let sessionId: string;
  try {
    sessionId = extractSessionId(event);
  } catch (error: unknown) {
    if ((error as { preflight?: boolean }).preflight)
      return { statusCode: 204 };
    throw error;
  }

  const session = await lookupSession(sessionId);
  const fullPayload = await fetchPayload(sessionId);

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

  if (fullPayload) {
    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fullPayload),
    };
  }
  return buildFallbackResponse(session, sessionId);
};

// ==================== EXPORT WITH MIDDLEWARE ====================

export const handler = middy(baseHandler)
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
  .use(jsonErrorHandler({ logger }));
