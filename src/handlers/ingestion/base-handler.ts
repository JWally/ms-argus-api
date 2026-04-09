/**
 * Base HTTP handler for ingestion endpoint.
 *
 * Provides core request handling logic for the /v1/collect endpoint,
 * including routing, SQS message dispatch, and payload archiving.
 * @module
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import {
  ConditionalCheckFailedException,
  DynamoDBClient,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import { getSessionId, type ArgusPayload } from "../../helpers/payload-schema";
import { redeemSigintTokens } from "../../helpers/redeem-sigint-tokens";
import { detectNetworkProbeAnomalies } from "../../services/profile/anomaly/network-probe-detector";
import type { Fingerprint } from "../../types";

/** API Gateway event extended with pre-parsed body from middleware. */
export interface ExtendedEvent extends APIGatewayProxyEventV2 {
  /** Validated and parsed Argus payload from middleware */
  parsedBody?: ArgusPayload;
}

/** Dependencies required for the base ingestion handler. */
export interface BaseHandlerDeps {
  /** SQS client for queueing fingerprints */
  sqs: SQSClient;
  /** URL of the matching worker queue */
  sqsQueueUrl: string;
  /** Logger instance for structured logging */
  logger: Logger;
  /** Metrics client for CloudWatch metrics */
  metrics: Metrics;
}

/**
 * Route incoming request to appropriate handler.
 *
 * Handles health checks, OPTIONS preflight, and validates method/path.
 * Returns early response for health/OPTIONS, null for valid POST requests.
 *
 * @param event - API Gateway event
 * @returns Early response or null to continue processing
 * @throws HttpError for invalid method or path
 */
async function routeRequest(
  event: ExtendedEvent,
): Promise<APIGatewayProxyResultV2 | null> {
  const method = event.requestContext.http.method;

  if (event.rawPath === "/health") {
    return { statusCode: 200, body: JSON.stringify({ status: "healthy" }) };
  }
  if (method === "OPTIONS") {
    return { statusCode: 204 };
  }
  if (method !== "POST") {
    throw new HttpError(405, "Method not allowed");
  }
  if (
    event.rawPath !== "/v1/collect" &&
    event.rawPath !== "/v1/integrity-collect"
  ) {
    throw new HttpError(404, "Not found");
  }
  return null;
}

/**
 * Create the base ingestion handler function.
 *
 * Factory that returns an async handler for processing fingerprint
 * collection requests. Queues payloads to SQS for matching worker
 * and optionally archives to S3 for analysis.
 *
 * @param deps - Handler dependencies including AWS clients
 * @returns Async handler function for API Gateway events
 */
const ddbClient = new DynamoDBClient({});
const INTEGRITY_RESULTS_TABLE = process.env.INTEGRITY_RESULTS_TABLE ?? "";
const INTEGRITY_TTL_SECONDS = 3600; // 1 hour

export function createBaseHandler(deps: BaseHandlerDeps) {
  return async (event: ExtendedEvent): Promise<APIGatewayProxyResultV2> => {
    const start = Date.now();

    const earlyResponse = await routeRequest(event);
    if (earlyResponse) return earlyResponse;

    const payload = event.parsedBody as ArgusPayload;
    const sessionId = getSessionId(payload);

    if (event.rawPath === "/v1/integrity-collect") {
      return handleIntegrity({ payload, sessionId, event, deps, start });
    }

    return handleCollect({ payload, sessionId, event, deps, start });
  };
}

interface HandleContext {
  payload: ArgusPayload;
  sessionId: string;
  event: ExtendedEvent;
  deps: BaseHandlerDeps;
  start: number;
}

async function handleCollect(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const { payload, sessionId, event, deps, start } = ctx;
  const sqsPayload = {
    ...payload,
    _headers: {
      "User-Agent": event.headers["user-agent"],
      "Accept-Language": event.headers["accept-language"],
      "X-Forwarded-For": event.headers["x-forwarded-for"],
    },
    _timestamp: Date.now(),
  };

  try {
    await deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: deps.sqsQueueUrl,
        MessageBody: JSON.stringify(sqsPayload),
      }),
    );
  } catch (err) {
    deps.logger.error("SQS send failed", {
      error: err,
      session_id: sessionId,
    });
    deps.metrics.addMetric("SqsSendFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }

  deps.metrics.addMetric("RequestQueued", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "IngestionDuration",
    MetricUnit.Milliseconds,
    Date.now() - start,
  );

  return {
    statusCode: 200,
    body: JSON.stringify({ session_id: sessionId }),
    headers: { "Content-Type": "application/json" },
  };
}

async function hydrateSigint(
  payload: ArgusPayload,
  deps: BaseHandlerDeps,
): Promise<ArgusPayload> {
  const sigintAesKey = process.env.SIGINT_AES_KEY;
  const probeTokensTable = process.env.PROBE_TOKENS_TABLE_NAME;
  if (!sigintAesKey || !probeTokensTable) return payload;

  try {
    const hydrated = await redeemSigintTokens(payload, {
      sigintAesKeyHex: sigintAesKey,
      probeTokensTableName: probeTokensTable,
      dynamo: ddbClient,
      logger: deps.logger,
    });
    deps.metrics.addMetric("IntegritySigintRedeemed", MetricUnit.Count, 1);
    return hydrated;
  } catch (err) {
    deps.logger.warn("Sigint token redemption failed", { error: err });
    return payload;
  }
}

function analyzeNetworkProbes(sigint: unknown) {
  const networkSignals = detectNetworkProbeAnomalies(
    {} as Fingerprint,
    undefined,
    sigint,
  );
  const maxScore = (code: string) => {
    const matching = networkSignals.filter((s) => s.code === code);
    return matching.length ? Math.max(...matching.map((s) => s.severity)) : 0;
  };
  return {
    proxy_score: maxScore("LIKELY_PROXY"),
    vpn_score: maxScore("LIKELY_VPN"),
    signals: networkSignals.map((s) => ({
      code: s.code,
      severity: s.severity,
      evidence: s.evidence.actual,
    })),
  };
}

function sigintSummary(payload: ArgusPayload): Record<string, string> {
  const present = (v: unknown) => (v ? "present" : "absent");
  return {
    tls: present(payload.sigintTls),
    tcp_token: present(payload.sigintTcpToken),
    h2_token: present(payload.sigintH2Token),
  };
}

function buildIntegrityItem(ctx: HandleContext, hydratedPayload: ArgusPayload) {
  const now = Date.now();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = ctx.payload as any;
  const vmSignals: string[] = raw.vmSignals ?? [];

  return {
    session_id: ctx.sessionId,
    tampered: raw.tampered ?? false,
    vm_signals: vmSignals,
    vm_hash: raw.vmHash ?? "",
    signal_count: vmSignals.length,
    device: raw.device ?? {},
    meta: raw.meta ?? {},
    sigint: hydratedPayload.sigint ?? sigintSummary(ctx.payload),
    network_analysis: analyzeNetworkProbes(hydratedPayload.sigint),
    client_ip:
      ctx.event.headers["x-forwarded-for"]?.split(",")[0]?.trim() ?? "",
    user_agent: ctx.event.headers["user-agent"] ?? "",
    created_at: now,
    ttl: Math.floor(now / 1000) + INTEGRITY_TTL_SECONDS,
  };
}

async function handleIntegrity(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const hydratedPayload = await hydrateSigint(ctx.payload, ctx.deps);
  const item = buildIntegrityItem(ctx, hydratedPayload);

  try {
    await ddbClient.send(
      new PutItemCommand({
        TableName: INTEGRITY_RESULTS_TABLE,
        Item: marshall(item, { removeUndefinedValues: true }),
        ConditionExpression: "attribute_not_exists(session_id)",
      }),
    );
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      ctx.deps.metrics.addMetric("IntegrityReplayBlocked", MetricUnit.Count, 1);
      throw new HttpError(409, "Session already processed");
    }
    ctx.deps.logger.error("Integrity DynamoDB write failed", {
      error: err,
      session_id: ctx.sessionId,
    });
    ctx.deps.metrics.addMetric("IntegrityWriteFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }

  ctx.deps.metrics.addMetric("IntegrityStored", MetricUnit.Count, 1);
  ctx.deps.metrics.addMetric(
    "IntegrityDuration",
    MetricUnit.Milliseconds,
    Date.now() - ctx.start,
  );

  return {
    statusCode: 200,
    body: JSON.stringify({ session_id: ctx.sessionId }),
    headers: { "Content-Type": "application/json" },
  };
}
