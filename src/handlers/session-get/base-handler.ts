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
import { SessionCacheValue } from "../../types/matching";
import {
  extractSessionId,
  lookupSession,
  fetchPayload,
  fetchVectorResults,
  fetchIntegrityResults,
  buildFallbackResponse,
} from "./session-ops";
import { validateIntegrityApiKey } from "../../helpers/integrity-api-key";

/**
 * Dependencies required by the session-get handler.
 */
interface HandlerDeps {
  dynamodb: DynamoDBClient;
  cacheService: DynamoCacheService;
  payloadTable: string;
  vectorResultsTable?: string;
  integrityResultsTable?: string;
  logger: Logger;
  metrics: Metrics;
}

/**
 * Emits CloudWatch metrics and structured logs for a session retrieval.
 */
function emitSessionMetrics(
  params: {
    session: SessionCacheValue;
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

/** Build success response with optional vector + integrity results */
function buildSuccessResponse(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fullPayload: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vectorResults?: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  integrityResults?: any,
): APIGatewayProxyResultV2 {
  const response = { ...fullPayload };
  if (vectorResults) response.vector_results = vectorResults;
  if (integrityResults) response.integrity = integrityResults;
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(response),
  };
}

const JSON_HEADERS = { "Content-Type": "application/json" };

/**
 * TODO(merchant-response-shaping): this endpoint currently returns the
 * full integrity record (device fingerprint, sigint blob, every analyzer
 * output, raw signals). That's fine for our internal use but a
 * reconnaissance gift for any merchant — and any bot that owns a
 * merchant account — once they realize they can call it.
 *
 * Before we expose this to merchants in production, replace
 * `integrityResults` with a stripped projection containing only fields
 * a fraud-prevention buyer needs:
 *   - score / decision (when scoring lands)
 *   - a small fixed set of merchant-safe flags (e.g. ip_lied,
 *     timezone_lied, asn_category, browser_family) — NOT the full
 *     analyzer evidence arrays
 *   - timestamps and the session id
 *
 * Keep DynamoDB storage as-is (full record); the shaping happens here in
 * the response layer. Internal tools (admin endpoint, dashboards, PW
 * tests) should read DDB / S3 directly with elevated auth, not via this
 * route. PW tests in ms-argus-web-integrity already do DDB-direct so they
 * won't silently break when this is tightened.
 */
async function handleIntegritySession(
  sessionId: string,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
  if (!deps.integrityResultsTable) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Integrity not configured" }),
    };
  }
  const integrityResults = await fetchIntegrityResults(sessionId, {
    dynamodb: deps.dynamodb,
    integrityResultsTable: deps.integrityResultsTable,
    logger: deps.logger,
    metrics: deps.metrics,
  });
  if (!integrityResults) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Session not found" }),
    };
  }
  deps.metrics.addMetric("IntegritySessionRetrieved", MetricUnit.Count, 1);
  return buildSuccessResponse(
    { session_id: sessionId },
    undefined,
    integrityResults,
  );
}

async function handleRegularSession(
  sessionId: string,
  startTime: number,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
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
}

/**
 * Factory function that creates the base session-get handler.
 */
export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyResultV2> => {
    const startTime = Date.now();

    const apiKey = event.headers["x-api-key"];
    const valid = await validateIntegrityApiKey(apiKey);
    if (!valid) {
      deps.metrics.addMetric("ApiKeyRejected", MetricUnit.Count, 1);
      return {
        statusCode: 401,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "Invalid or missing API key" }),
      };
    }

    let sessionId: string;
    try {
      sessionId = extractSessionId(event, deps.metrics);
    } catch (error: unknown) {
      if ((error as { preflight?: boolean }).preflight)
        return { statusCode: 204 };
      throw error;
    }

    if (event.rawPath.startsWith("/v1/integrity-session")) {
      return handleIntegritySession(sessionId, deps);
    }
    return handleRegularSession(sessionId, startTime, deps);
  };
}
