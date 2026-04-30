/**
 * @fileoverview Session retrieval handler.
 *
 * Mounted on the merchant REST API at:
 *   GET /v1/session/{cpi}/{session_id}
 *
 * Auth flow:
 *   - APIGW already matched `x-api-key` against its native key store before
 *     we run; we just read it back to bind the signed token to the same key.
 *   - `x-argus-token` carries the Ed25519-signed claims minted by
 *     ms-argus-platform — we verify the signature against the platform's
 *     SSM-published pubkey and assert claims.cpi === path.cpi for
 *     structural tenant isolation.
 *
 * @module handlers/session-get/base-handler
 */

import { APIGatewayProxyEvent, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  extractSessionId,
  fetchIntegrityResultsByComposite,
} from "./session-ops";
import { verifyMerchantToken } from "../../helpers/token-verifier";
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

interface HandlerDeps {
  dynamodb: DynamoDBClient;
  integrityResultsTable: string;
  logger: Logger;
  metrics: Metrics;
}

const JSON_HEADERS = { "Content-Type": "application/json" };
const CPI_FORMAT = /^argus_cpi_(test|live)_[A-Za-z0-9]{10,40}$/;

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

async function authorize(
  cpi: string,
  event: APIGatewayProxyEvent,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2 | null> {
  const keyIdHeader =
    event.headers?.["x-api-key"] ?? event.headers?.["X-Api-Key"];
  const tokenHeader =
    event.headers?.["x-argus-token"] ?? event.headers?.["X-Argus-Token"];
  const ssmPubkeyPath = process.env.PLATFORM_PUBKEY_SSM_PATH;
  if (!ssmPubkeyPath) {
    deps.logger.error("PLATFORM_PUBKEY_SSM_PATH not configured");
    return {
      statusCode: 500,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Verifier misconfigured" }),
    };
  }
  const claims = await verifyMerchantToken(keyIdHeader, tokenHeader, {
    ssmPubkeyPath,
    expectedCpi: cpi,
  });
  if (!claims) {
    deps.metrics.addMetric("MerchantTokenRejected", MetricUnit.Count, 1);
    return {
      statusCode: 401,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Invalid or missing token" }),
    };
  }
  deps.metrics.addMetric("MerchantTokenAccepted", MetricUnit.Count, 1);
  return null;
}

export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEvent,
  ): Promise<APIGatewayProxyResultV2> => {
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 204 };
    }

    const cpi = event.pathParameters?.cpi;
    if (!cpi || !CPI_FORMAT.test(cpi)) {
      deps.metrics.addMetric("InvalidCpi", MetricUnit.Count, 1);
      return {
        statusCode: 400,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "Invalid cpi parameter" }),
      };
    }
    const sessionId = extractSessionId(event, deps.metrics);
    const denied = await authorize(cpi, event, deps);
    if (denied) return denied;

    const integrity = await fetchIntegrityResultsByComposite(
      cpi,
      sessionId,
      deps,
    );
    if (!integrity) {
      return {
        statusCode: 404,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "Session not found" }),
      };
    }
    deps.metrics.addMetric("IntegritySessionRetrieved", MetricUnit.Count, 1);
    return buildIntegrityResponse({ sessionId, integrity });
  };
}
