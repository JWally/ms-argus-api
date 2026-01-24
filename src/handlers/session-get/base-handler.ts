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

interface HandlerDeps {
  dynamodb: DynamoDBClient;
  cacheService: DynamoCacheService;
  payloadTable: string;
  logger: Logger;
  metrics: Metrics;
}

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
