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
import {
  verifyMerchantToken,
  type VerifiedClaims,
} from "../../helpers/token-verifier";
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import { decrementCredit } from "../../helpers/credits";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

interface HandlerDeps {
  dynamodb: DynamoDBClient;
  integrityResultsTable: string;
  merchantsTable: string;
  logger: Logger;
  metrics: Metrics;
}

const JSON_HEADERS = { "Content-Type": "application/json" };
const CPI_FORMAT = /^argus_cpi_(test|live)_[A-Za-z0-9]{10,40}$/;

function buildIntegrityResponse(params: {
  sessionId: string;
  integrity: IntegrityResultsData;
  creditsRemaining: number;
}): APIGatewayProxyResultV2 {
  const merchant = buildMerchantResponse({
    session_id: params.sessionId,
    integrity: params.integrity,
  });
  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({
      ...merchant,
      creditsRemaining: params.creditsRemaining,
    }),
  };
}

type AuthorizeResult =
  | { ok: true; claims: VerifiedClaims }
  | { ok: false; response: APIGatewayProxyResultV2 };

async function authorize(
  cpi: string,
  event: APIGatewayProxyEvent,
  deps: HandlerDeps,
): Promise<AuthorizeResult> {
  const keyIdHeader =
    event.headers?.["x-api-key"] ?? event.headers?.["X-Api-Key"];
  const tokenHeader =
    event.headers?.["x-argus-token"] ?? event.headers?.["X-Argus-Token"];
  const ssmPubkeyPath = process.env.PLATFORM_PUBKEY_SSM_PATH;
  if (!ssmPubkeyPath) {
    deps.logger.error("PLATFORM_PUBKEY_SSM_PATH not configured");
    return {
      ok: false,
      response: {
        statusCode: 500,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "Verifier misconfigured" }),
      },
    };
  }
  const claims = await verifyMerchantToken(keyIdHeader, tokenHeader, {
    ssmPubkeyPath,
    expectedCpi: cpi,
  });
  if (!claims) {
    deps.metrics.addMetric("MerchantTokenRejected", MetricUnit.Count, 1);
    return {
      ok: false,
      response: {
        statusCode: 401,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "Invalid or missing token" }),
      },
    };
  }
  deps.metrics.addMetric("MerchantTokenAccepted", MetricUnit.Count, 1);
  return { ok: true, claims };
}

type DebitResult =
  | { ok: true; remaining: number }
  | { ok: false; response: APIGatewayProxyResultV2 };

/**
 * Burn one credit for this billable read. Atomic conditional decrement on
 * the merchants table — if balance is zero, return 402 before any integrity-
 * results work so we don't hand out data we won't be paid for.
 */
async function debitCreditOr402(
  merchantId: string,
  deps: HandlerDeps,
): Promise<DebitResult> {
  const debit = await decrementCredit(merchantId, {
    ddb: deps.dynamodb,
    table: deps.merchantsTable,
  });
  if (!debit.ok) {
    deps.metrics.addMetric("InsufficientCredits", MetricUnit.Count, 1);
    return {
      ok: false,
      response: {
        statusCode: 402,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "insufficient_credits" }),
      },
    };
  }
  deps.metrics.addMetric("CreditBurned", MetricUnit.Count, 1);
  return { ok: true, remaining: debit.remaining };
}

/**
 * The billable read pipeline: verify token → burn a credit → fetch integrity
 * → project. Each phase is timed; a single structured line breaks down the
 * warm-path latency (token verify / SSM, credit DDB, integrity DDB, projection
 * CPU). performance.now() is a monotonic ms clock.
 */
async function runTimedPipeline(
  cpi: string,
  sessionId: string,
  event: APIGatewayProxyEvent,
  deps: HandlerDeps,
): Promise<APIGatewayProxyResultV2> {
  const t0 = performance.now();
  const auth = await authorize(cpi, event, deps);
  if (!auth.ok) return auth.response;
  const tAuth = performance.now();

  const debit = await debitCreditOr402(auth.claims.merchantId, deps);
  if (!debit.ok) return debit.response;
  const tDebit = performance.now();

  const integrity = await fetchIntegrityResultsByComposite(
    cpi,
    sessionId,
    deps,
  );
  const tFetch = performance.now();
  if (!integrity) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "Session not found" }),
    };
  }
  deps.metrics.addMetric("IntegritySessionRetrieved", MetricUnit.Count, 1);
  const response = buildIntegrityResponse({
    sessionId,
    integrity,
    creditsRemaining: debit.remaining,
  });
  const tProject = performance.now();

  deps.logger.info("session-get timing", {
    authMs: Math.round(tAuth - t0),
    debitMs: Math.round(tDebit - tAuth),
    fetchMs: Math.round(tFetch - tDebit),
    projectMs: Math.round(tProject - tFetch),
    totalMs: Math.round(tProject - t0),
  });
  return response;
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
    return runTimedPipeline(cpi, sessionId, event, deps);
  };
}
