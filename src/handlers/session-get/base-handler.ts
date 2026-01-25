/**
 * @fileoverview Base handler factory for session retrieval endpoint.
 * Creates the core handler logic for GET /v1/session/{session_id}.
 * @module handlers/session-get/base-handler
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoCacheService } from "../../services/cache/dynamo-cache";
import {
  extractSessionId,
  lookupSession,
  fetchPayload,
  buildFallbackResponse,
} from "./session-ops";

/**
 * Dependencies required by the session-get handler.
 *
 * @interface HandlerDeps
 */
interface HandlerDeps {
  dynamodb: DynamoDBClient;
  cacheService: DynamoCacheService;
  payloadTable: string;
  logger: Logger;
  metrics: Metrics;
}

/**
 * Emits CloudWatch metrics and structured logs for a session retrieval.
 *
 * Records:
 * - SessionRetrieved count
 * - SessionGetDuration latency
 * - Structured log with session details
 *
 * @param params - Metrics data
 * @param params.session - Retrieved session data
 * @param params.sessionId - Session identifier
 * @param params.duration - Handler execution time in ms
 * @param params.hasPayload - Whether full payload was available
 * @param deps - Handler dependencies with metrics instance
 *
 * @internal
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function emitSessionMetrics(
  params: {
    session: any;
    sessionId: string;
    duration: number;
    hasPayload: boolean;
  },
  deps: HandlerDeps,
): void {
  deps.logger.info("Session retrieved", {
    session_id: params.sessionId,
    status: params.session.status,
    device_id: params.session.device_id,
    duration_ms: params.duration,
    has_payload: params.hasPayload,
  });
  deps.metrics.addMetric("SessionRetrieved", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "SessionGetDuration",
    MetricUnit.Milliseconds,
    params.duration,
  );
}

/**
 * Factory function that creates the base session-get handler.
 *
 * The returned handler:
 * 1. Extracts and validates the session ID from path parameters
 * 2. Looks up the session in the cache
 * 3. Attempts to fetch the full payload from the payload table
 * 4. Returns full payload if available, or degraded response if not
 *
 * @param deps - Handler dependencies
 * @returns Async handler function for API Gateway
 *
 * @example
 * ```typescript
 * const baseHandler = createBaseHandler({
 *   dynamodb,
 *   cacheService,
 *   payloadTable: "session-payloads",
 *   logger,
 *   metrics,
 * });
 *
 * export const handler = middy(baseHandler)
 *   .use(corsMiddleware({ methods: "GET, OPTIONS", headers: "Content-Type" }))
 *   .use(jsonErrorHandler({ logger }));
 * ```
 */
export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyResultV2> => {
    const startTime = Date.now();
    let sessionId: string;
    try {
      sessionId = extractSessionId(event, deps.metrics);
    } catch (error: unknown) {
      if ((error as { preflight?: boolean }).preflight)
        return { statusCode: 204 };
      throw error;
    }

    const session = await lookupSession(sessionId, {
      cacheService: deps.cacheService,
      logger: deps.logger,
      metrics: deps.metrics,
    });
    const fullPayload = await fetchPayload(sessionId, {
      dynamodb: deps.dynamodb,
      payloadTable: deps.payloadTable,
      logger: deps.logger,
      metrics: deps.metrics,
    });

    emitSessionMetrics(
      {
        session,
        sessionId,
        duration: Date.now() - startTime,
        hasPayload: !!fullPayload,
      },
      deps,
    );

    if (fullPayload) {
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fullPayload),
      };
    }
    return buildFallbackResponse(session, sessionId, deps.metrics);
  };
}
