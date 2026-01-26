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
  fetchVectorResults,
  buildFallbackResponse,
} from "./session-ops";

/**
 * Dependencies required by the session-get handler.
 */
interface HandlerDeps {
  dynamodb: DynamoDBClient;
  cacheService: DynamoCacheService;
  payloadTable: string;
  vectorResultsTable?: string;
  logger: Logger;
  metrics: Metrics;
}

/**
 * Emits CloudWatch metrics and structured logs for a session retrieval.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function emitSessionMetrics(
  params: {
    session: any;
    sessionId: string;
    duration: number;
    hasPayload: boolean;
  },
  deps: Pick<HandlerDeps, "logger" | "metrics">,
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

/** Build success response with optional vector results */
function buildSuccessResponse(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fullPayload: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vectorResults?: any,
): APIGatewayProxyResultV2 {
  const response = vectorResults
    ? { ...fullPayload, vector_results: vectorResults }
    : fullPayload;
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(response),
  };
}

/**
 * Factory function that creates the base session-get handler.
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

    let vectorResults;
    if (deps.vectorResultsTable) {
      vectorResults = await fetchVectorResults(sessionId, {
        dynamodb: deps.dynamodb,
        vectorResultsTable: deps.vectorResultsTable,
        logger: deps.logger,
        metrics: deps.metrics,
      });
    }

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
      return buildSuccessResponse(fullPayload, vectorResults);
    }
    return buildFallbackResponse(session, sessionId, deps.metrics);
  };
}
