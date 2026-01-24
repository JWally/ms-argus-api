import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { gunzipSync } from "zlib";
import { DynamoCacheService } from "../../services/cache/dynamo-cache";
import { HttpError } from "../../helpers/http-error";
import {
  validateSessionResponse,
  type SessionResponse,
} from "../../helpers/payload-schema";

export function extractSessionId(
  event: APIGatewayProxyEventV2,
  metrics: Metrics,
): string {
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

export async function lookupSession(
  sessionId: string,
  deps: { cacheService: DynamoCacheService; logger: Logger; metrics: Metrics },
) {
  try {
    const session = await deps.cacheService.checkSessionCache(sessionId);
    if (!session) {
      deps.metrics.addMetric("SessionNotFound", MetricUnit.Count, 1);
      throw new HttpError(404, "Session not found");
    }
    return session;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    deps.logger.error("Failed to retrieve session", {
      error,
      session_id: sessionId,
    });
    deps.metrics.addMetric("SessionGetFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }
}

export async function fetchPayload(
  sessionId: string,
  deps: {
    dynamodb: DynamoDBClient;
    payloadTable: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<SessionResponse | undefined> {
  try {
    const result = await deps.dynamodb.send(
      new GetItemCommand({
        TableName: deps.payloadTable,
        Key: { session_id: { S: sessionId } },
      }),
    );
    if (!result.Item?.payload_gzip_b64?.S) return undefined;
    const gzipBuffer = Buffer.from(result.Item.payload_gzip_b64.S, "base64");
    const parsed = JSON.parse(gunzipSync(gzipBuffer).toString("utf-8"));
    const validated = validateSessionResponse(parsed);
    deps.metrics.addMetric("SessionPayloadFound", MetricUnit.Count, 1);
    return validated;
  } catch (error) {
    deps.logger.warn("Failed to fetch/validate session payload", {
      error,
      session_id: sessionId,
    });
    deps.metrics.addMetric("SessionPayloadFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildFallbackResponse(
  session: any,
  sessionId: string,
  metrics: Metrics,
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
