/**
 * @fileoverview Session retrieval operations for the session-get handler.
 * Provides session ID extraction, cache lookup, payload fetching, and response building.
 * @module handlers/session-get/session-ops
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { gunzipSync } from "zlib";
import { DynamoCacheService } from "../../services/cache/dynamo-cache";
import { HttpError } from "../../helpers/http-error";
import {
  validateSessionResponse,
  type SessionResponse,
} from "../../helpers/payload-schema";
import { SessionCacheValue } from "../../types/matching";

/**
 * Extracts and validates the session ID from the API Gateway event.
 *
 * Handles:
 * - OPTIONS preflight requests (throws special error with preflight flag)
 * - Method validation (only GET allowed)
 * - Session ID presence and format validation
 *
 * @param event - API Gateway proxy event
 * @param metrics - Metrics instance for tracking validation failures
 * @returns Validated session ID string
 *
 * @throws {HttpError} with preflight=true for OPTIONS requests
 * @throws {HttpError} 405 for non-GET methods
 * @throws {HttpError} 400 for missing or invalid session ID format
 *
 * @example
 * ```typescript
 * try {
 *   const sessionId = extractSessionId(event, metrics);
 * } catch (error) {
 *   if ((error as any).preflight) return { statusCode: 204 };
 *   throw error;
 * }
 * ```
 */
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
  if (sessionId.length > 1024 || !/^[\w-]+$/.test(sessionId)) {
    metrics.addMetric("InvalidSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Invalid session_id format");
  }
  return sessionId;
}

/**
 * Looks up a session in the DynamoDB cache.
 *
 * @param sessionId - Session identifier to look up
 * @param deps - Service dependencies
 * @param deps.cacheService - DynamoDB cache service instance
 * @param deps.logger - Logger for error output
 * @param deps.metrics - Metrics for tracking lookup outcomes
 * @returns Cached session data if found
 *
 * @throws {HttpError} 404 if session not found in cache
 * @throws {HttpError} 503 if cache lookup fails due to service error
 *
 * @example
 * ```typescript
 * const session = await lookupSession(sessionId, { cacheService, logger, metrics });
 * console.log(session.device_id, session.status);
 * ```
 */
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

/**
 * Fetches the full session payload from DynamoDB.
 *
 * The payload is stored gzip-compressed and base64-encoded to reduce storage costs.
 * This function handles decompression and JSON parsing, then validates the response
 * schema before returning.
 *
 * @param sessionId - Session identifier to fetch payload for
 * @param deps - Service dependencies
 * @param deps.dynamodb - DynamoDB client instance
 * @param deps.payloadTable - Table name for session payloads
 * @param deps.logger - Logger for warning on failures
 * @param deps.metrics - Metrics for tracking fetch outcomes
 * @returns Full session response if found and valid, undefined otherwise
 *
 * @example
 * ```typescript
 * const payload = await fetchPayload(sessionId, deps);
 * if (payload) {
 *   return { statusCode: 200, body: JSON.stringify(payload) };
 * }
 * ```
 */
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

/**
 * Builds a degraded response when the full session payload is unavailable.
 *
 * Returns a minimal response using only the cached session data. The response
 * includes an X-Argus-Degraded header to indicate incomplete data. This ensures
 * clients always receive a response even if the payload table is unavailable.
 *
 * @param session - Cached session data (minimal fields)
 * @param sessionId - Session identifier for the response
 * @param metrics - Metrics for tracking degraded responses
 * @returns API Gateway response with degraded session data
 *
 * @example
 * ```typescript
 * const payload = await fetchPayload(sessionId, deps);
 * if (!payload) {
 *   return buildFallbackResponse(session, sessionId, metrics);
 * }
 * ```
 */
export function buildFallbackResponse(
  session: SessionCacheValue,
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

/**
 * Result from a vector search
 */
export interface VectorResult {
  id: string;
  score: number;
  payload?: Record<string, unknown>;
}

/**
 * Vector results stored in DynamoDB
 */
export interface VectorResultsData {
  session_id: string;
  results: VectorResult[];
  collection: string;
  result_count: number;
  top_score: number | null;
  created_at: number;
}

/**
 * Fetches vector search results from DynamoDB.
 *
 * Vector results are written by the vector-results-writer Lambda after
 * vector searches complete. Results have a 5-minute TTL.
 *
 * @param sessionId - Session identifier to fetch results for
 * @param deps - Service dependencies
 * @param deps.dynamodb - DynamoDB client instance
 * @param deps.vectorResultsTable - Table name for vector results
 * @param deps.logger - Logger for warning on failures
 * @param deps.metrics - Metrics for tracking fetch outcomes
 * @returns Vector results if found, undefined otherwise
 */
export async function fetchVectorResults(
  sessionId: string,
  deps: {
    dynamodb: DynamoDBClient;
    vectorResultsTable: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<VectorResultsData | undefined> {
  try {
    const result = await deps.dynamodb.send(
      new GetItemCommand({
        TableName: deps.vectorResultsTable,
        Key: { session_id: { S: sessionId } },
      }),
    );

    if (!result.Item) {
      deps.metrics.addMetric("VectorResultsNotFound", MetricUnit.Count, 1);
      return undefined;
    }

    // Unmarshall the DynamoDB item to native JavaScript types
    const item = unmarshall(result.Item) as VectorResultsData;

    deps.metrics.addMetric("VectorResultsFound", MetricUnit.Count, 1);
    return item;
  } catch (error) {
    deps.logger.warn("Failed to fetch vector results", {
      error,
      session_id: sessionId,
    });
    deps.metrics.addMetric("VectorResultsFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}

/**
 * Integrity results data shape stored in DynamoDB.
 */
interface IntegrityResultsData {
  session_id: string;
  tampered: boolean;
  vm_signals: string[];
  vm_hash: string;
  signal_count: number;
  hashes: Record<string, string>;
  device_summary: Record<string, string>;
  sigint: Record<string, string>;
  client_ip: string;
  user_agent: string;
  created_at: number;
}

/**
 * Fetches integrity check results from DynamoDB.
 *
 * Integrity results are written by the ingestion Lambda when handling
 * POST /v1/integrity. Results have a 1-hour TTL.
 */
export async function fetchIntegrityResults(
  sessionId: string,
  deps: {
    dynamodb: DynamoDBClient;
    integrityResultsTable: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<IntegrityResultsData | undefined> {
  try {
    const result = await deps.dynamodb.send(
      new GetItemCommand({
        TableName: deps.integrityResultsTable,
        Key: { session_id: { S: sessionId } },
      }),
    );

    if (!result.Item) {
      deps.metrics.addMetric("IntegrityResultsNotFound", MetricUnit.Count, 1);
      return undefined;
    }

    const item = unmarshall(result.Item) as IntegrityResultsData;
    deps.metrics.addMetric("IntegrityResultsFound", MetricUnit.Count, 1);
    return item;
  } catch (error) {
    deps.logger.warn("Failed to fetch integrity results", {
      error,
      session_id: sessionId,
    });
    deps.metrics.addMetric("IntegrityResultsFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}
