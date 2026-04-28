/**
 * @fileoverview Session retrieval handler.
 *
 * Two routes converge into one Lambda:
 *
 *   - NEW (merchant-facing, REST API + native APIGW Keys):
 *       GET /v1/session/{cpi}/{session_id}
 *       Auth: signed Ed25519 token in `x-api-key` (verified in-process; the
 *       gateway has already matched the keyId portion against its key store).
 *       Path's `cpi` must equal the token's `cpi` claim — structural
 *       tenant isolation.
 *
 *   - LEGACY (HTTP API, internal callers):
 *       GET /v1/integrity-session/{session_id}
 *       Auth: shared SSM secret in `x-api-key`. Still gated by the
 *       `ENABLE_LEGACY_SHARED_SECRET` env flag so we can flip it off when
 *       all callers have migrated. LEGACY_SHARED_SECRET_AUTH.
 *
 * @module handlers/session-get/base-handler
 */

import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  extractSessionId,
  fetchIntegrityResultsByComposite,
  fetchIntegrityResultsBySessionIdLegacy,
} from "./session-ops";
import { validateIntegrityApiKey } from "../../helpers/integrity-api-key";
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

function isMerchantRoute(event: APIGatewayProxyEventV2): boolean {
  // REST API and HTTP API differ in event shape; routeKey is HTTP API only.
  // Use the path the request actually arrived on as the source of truth.
  return /\/v1\/session\/[^/]+\/[^/]+/.test(event.rawPath ?? "");
}

async function authorizeMerchantRequest(
  cpi: string,
  event: APIGatewayProxyEventV2,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2 | null> {
  const tokenHeader = event.headers["x-api-key"] ?? event.headers["X-Api-Key"];
  const ssmPubkeyPath = process.env.PLATFORM_PUBKEY_SSM_PATH;
  if (!ssmPubkeyPath) {
    deps.logger.error("PLATFORM_PUBKEY_SSM_PATH not configured");
    return {
      statusCode: 500,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Verifier misconfigured" }),
    };
  }
  const claims = await verifyMerchantToken(tokenHeader, {
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

async function handleMerchantRoute(
  event: APIGatewayProxyEventV2,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
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
  const denied = await authorizeMerchantRequest(cpi, event, deps);
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
}

/**
 * LEGACY_SHARED_SECRET_AUTH — old route gated by shared SSM secret.
 * Drops alongside `fetchIntegrityResultsBySessionIdLegacy` and the
 * legacySessionIdIndex GSI when ENABLE_LEGACY_SHARED_SECRET=false.
 */
async function handleLegacyRoute(
  event: APIGatewayProxyEventV2,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
  if ((process.env.ENABLE_LEGACY_SHARED_SECRET ?? "true") !== "true") {
    deps.metrics.addMetric("LegacyAuthRejected", MetricUnit.Count, 1);
    return {
      statusCode: 410,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        error:
          "Deprecated route disabled. Migrate to GET /v1/session/{cpi}/{session_id}",
      }),
    };
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
  deps.metrics.addMetric("LegacyAuthUsed", MetricUnit.Count, 1);

  const sessionId = extractSessionId(event, deps.metrics);
  const integrity = await fetchIntegrityResultsBySessionIdLegacy(
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
}

export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyResultV2> => {
    // Short-circuit CORS preflight before auth — OPTIONS has no x-api-key.
    if (event.requestContext.http.method === "OPTIONS") {
      return { statusCode: 204 };
    }

    if (isMerchantRoute(event)) {
      return handleMerchantRoute(event, deps);
    }
    return handleLegacyRoute(event, deps);
  };
}
