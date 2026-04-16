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
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import type {
  IntegrityResultsData,
  SessionResponse,
} from "../../helpers/payload-schema";

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

/**
 * Build a regular-session response for the internal `/v1/session` path.
 * Retains the rich fullPayload + vector_results + merchant projection —
 * internal dashboards and tools read this route with elevated auth.
 */
function buildRegularSessionResponse(params: {
  sessionId: string;
  fullPayload?: SessionResponse;
  session?: SessionCacheValue;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vectorResults?: any;
}): APIGatewayProxyResultV2 {
  const merchant = buildMerchantResponse({
    session_id: params.sessionId,
    session: params.session,
    payload: params.fullPayload,
  });
  const response: Record<string, unknown> = params.fullPayload
    ? { ...params.fullPayload, merchant }
    : { merchant, session_id: params.sessionId };
  if (params.vectorResults) response.vector_results = params.vectorResults;
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(response),
  };
}

/**
 * Build the merchant-facing integrity response.
 *
 * Returns ONLY the merchant-safe projection (spread at the top level).
 * Does NOT return the raw integrity record — fingerprint, sigint blob,
 * analyzer evidence, and raw signals are a reconnaissance gift and
 * deliberately withheld. Internal tools that need the raw record should
 * read DynamoDB / S3 directly with elevated auth, not via this route.
 */
function buildIntegrityResponse(params: {
  sessionId: string;
  session?: SessionCacheValue;
  integrity: IntegrityResultsData;
}): APIGatewayProxyResultV2 {
  const merchant = buildMerchantResponse({
    session_id: params.sessionId,
    session: params.session,
    integrity: params.integrity,
  });
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(merchant),
  };
}

const JSON_HEADERS = { "Content-Type": "application/json" };

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
  // Best-effort session lookup for flag/confidence data in the projection.
  // Integrity endpoint must not 404 just because the session cache expired,
  // so swallow lookup failures.
  let session: SessionCacheValue | undefined;
  try {
    session = await lookupSession(sessionId, {
      cacheService: deps.cacheService,
      logger: deps.logger,
      metrics: deps.metrics,
    });
  } catch {
    session = undefined;
  }
  return buildIntegrityResponse({
    sessionId,
    session,
    integrity: integrityResults,
  });
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
    return buildRegularSessionResponse({
      sessionId,
      fullPayload,
      session,
      vectorResults,
    });
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

    // Short-circuit CORS preflight before auth — OPTIONS has no X-Api-Key.
    // The cors middleware attaches ACAO/ACAC headers in its `after` hook.
    if (event.requestContext.http.method === "OPTIONS") {
      return { statusCode: 204 };
    }

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
