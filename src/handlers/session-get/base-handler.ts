/** HTTP adapter for the merchant session retrieval application use case. */
import type { APIGatewayProxyEvent, APIGatewayProxyResultV2 } from "aws-lambda";
import type { Logger } from "@aws-lambda-powertools/logger";
import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type {
  SessionGetRequest,
  SessionGetResult,
} from "../../application/session-get";
import { parseSdkAttestationHeaders } from "../../helpers/sdk-attestation";
import { extractSessionId } from "./session-ops";

interface HandlerDeps {
  logger: Pick<Logger, "error">;
  metrics: Pick<Metrics, "addMetric">;
  getSession: (request: SessionGetRequest) => Promise<SessionGetResult>;
}

const JSON_HEADERS = { "Content-Type": "application/json" };
const CPI_FORMAT = /^argus_cpi_(test|live)_[A-Za-z0-9]{10,40}$/;

function jsonResponse(
  statusCode: number,
  body: Record<string, unknown>,
): APIGatewayProxyResultV2 {
  return { statusCode, headers: JSON_HEADERS, body: JSON.stringify(body) };
}

function mapApplicationResult(
  result: SessionGetResult,
  logger: Pick<Logger, "error">,
): APIGatewayProxyResultV2 {
  switch (result.kind) {
    case "ok":
      return jsonResponse(200, {
        ...result.projection,
        ...(result.attestation
          ? {
              attestation: {
                verified: true,
                keyId: result.attestation.keyId,
                payload: result.attestation.payload,
              },
            }
          : {}),
        creditsRemaining: result.creditsRemaining,
      });
    case "verifier_misconfigured":
      logger.error("PLATFORM_PUBKEY_SSM_PATH not configured");
      return jsonResponse(500, { error: "Verifier misconfigured" });
    case "unauthorized":
      return jsonResponse(401, { error: "Invalid or missing token" });
    case "invalid_attestation":
      return jsonResponse(400, {
        error: "Invalid attestation",
        reason: result.reason,
      });
    case "insufficient_credits":
      return jsonResponse(402, { error: "insufficient_credits" });
    case "not_found":
      return jsonResponse(404, { error: "Session not found" });
  }
}

function getHeader(
  event: APIGatewayProxyEvent,
  lowerName: string,
  titleName: string,
): string | undefined {
  return event.headers?.[lowerName] ?? event.headers?.[titleName];
}

function toApplicationRequest(
  cpi: string,
  sessionId: string,
  event: APIGatewayProxyEvent,
): SessionGetRequest {
  return {
    cpi,
    sessionId,
    apiKey: getHeader(event, "x-api-key", "X-Api-Key"),
    merchantToken: getHeader(event, "x-argus-token", "X-Argus-Token"),
    attestation: parseSdkAttestationHeaders(event.headers) ?? undefined,
  };
}

export function createBaseHandler(deps: HandlerDeps) {
  return async (
    event: APIGatewayProxyEvent,
  ): Promise<APIGatewayProxyResultV2> => {
    if (event.httpMethod === "OPTIONS") return { statusCode: 204 };
    const cpi = event.pathParameters?.cpi;
    if (!cpi || !CPI_FORMAT.test(cpi)) {
      deps.metrics.addMetric("InvalidCpi", MetricUnit.Count, 1);
      return jsonResponse(400, { error: "Invalid cpi parameter" });
    }
    const sessionId = extractSessionId(event, deps.metrics);
    const result = await deps.getSession(
      toApplicationRequest(cpi, sessionId, event),
    );
    return mapApplicationResult(result, deps.logger);
  };
}
