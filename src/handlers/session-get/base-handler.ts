/**
 * @fileoverview Base handler factory for session retrieval endpoint.
 * Serves only GET /v1/integrity-session/{session_id} — the merchant-safe
 * projection of a stored integrity record. The older /v1/session path
 * (regular fingerprint matching) was removed along with the matching
 * pipeline in remove-fingerprint.
 * @module handlers/session-get/base-handler
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { extractSessionId, fetchIntegrityResults } from "./session-ops";
import { validateIntegrityApiKey } from "../../helpers/integrity-api-key";
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

interface HandlerDeps {
  dynamodb: DynamoDBClient;
  integrityResultsTable: string;
  logger: Logger;
  metrics: Metrics;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

function buildIntegrityResponse(params: {
  sessionId: string;
  integrity: IntegrityResultsData;
}): APIGatewayProxyResultV2 {
  const merchant = buildMerchantResponse({
    session_id: params.sessionId,
    integrity: params.integrity,
  });
  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify(merchant),
  };
}

async function handleIntegritySession(
  sessionId: string,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
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
  return buildIntegrityResponse({ sessionId, integrity: integrityResults });
}

export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyResultV2> => {
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

    const sessionId = extractSessionId(event, deps.metrics);
    return handleIntegritySession(sessionId, deps);
  };
}
