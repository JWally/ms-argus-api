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
import { extractFpidCookie } from "../../helpers/verify-cf-token";
import {
  buildWebrtcSigintField,
  decodeWebrtcSigintCandidates,
  type SigintCandidateDecodeResult,
} from "../../helpers/sigint-v6-decode";
import {
  verifyDeviceIdentity,
  type IdentityOutcome,
} from "../../helpers/device-identity";
import {
  analyzeNetworkProbes,
  analyzeWorkerScopes,
  analyzeTimezone,
  analyzeIpConsistency,
  analyzeJa4Ua,
} from "../../analysis";

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

const UA_HEADER = "user-agent";
const XFF_HEADER = "x-forwarded-for";

async function handleCollect(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const { payload, sessionId, event, deps, start } = ctx;
  const sqsPayload = {
    ...payload,
    _headers: {
      "User-Agent": event.headers[UA_HEADER],
      "Accept-Language": event.headers["accept-language"],
      "X-Forwarded-For": event.headers[XFF_HEADER],
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
  event: ExtendedEvent,
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
      fpidCookie: extractFpidCookie(event.cookies),
    });
    deps.metrics.addMetric("IntegritySigintRedeemed", MetricUnit.Count, 1);
    return hydrated;
  } catch (err) {
    deps.logger.warn("Sigint token redemption failed", { error: err });
    return payload;
  }
}

function sigintSummary(payload: ArgusPayload): Record<string, string> {
  const present = (v: unknown) => (v ? "present" : "absent");
  return {
    tls: present(payload.sigintTls),
    tcp_token: present(payload.sigintTcpToken),
    h2_token: present(payload.sigintH2Token),
  };
}

/**
 * Build the `identification` column value from a verify outcome. Returns
 * undefined when the payload had no device_identity at all — saves a column on
 * legacy-bundle rows and keeps schemaless consumers unambiguous.
 */
function buildIdentificationField(
  outcome: IdentityOutcome,
): Record<string, unknown> | undefined {
  if (!outcome.present) return undefined;
  return {
    pubkey: outcome.pubkey,
    verified: outcome.verified,
    reason: outcome.verified ? null : outcome.reason,
    sig_present: outcome.sig_present,
  };
}

/**
 * Translate the sigint decode result into the evidence shape
 * analyzeIpConsistency wants. IP is populated only on the "ok" path;
 * forgery fires when candidates were submitted and none MAC-verified.
 */
function webrtcSigintEvidence(result: SigintCandidateDecodeResult): {
  ip: string | null;
  forgery: boolean;
} {
  return {
    ip: result.reason === "ok" ? (result.decoded?.ip ?? null) : null,
    forgery: result.reason === "forgery",
  };
}

function emitIdentityMetrics(
  deps: BaseHandlerDeps,
  outcome: IdentityOutcome,
): void {
  if (!outcome.present) {
    deps.metrics.addMetric("DeviceIdentityAbsent", MetricUnit.Count, 1);
    return;
  }
  if (outcome.verified) {
    deps.metrics.addMetric("DeviceIdentityVerified", MetricUnit.Count, 1);
    return;
  }
  deps.metrics.addMetric("DeviceIdentityVerifyFailed", MetricUnit.Count, 1);
  deps.logger.warn("Device identity verification failed", {
    reason: outcome.reason,
    sig_present: outcome.sig_present,
  });
}

// Request headers we preserve on the integrity record. Curated — not a blanket
// dump — because (a) DDB item size budget and (b) a few headers leak session
// state (Authorization, actual cookie values) and must not be archived.
const CAPTURED_REQUEST_HEADER_NAMES: readonly string[] = [
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "referer",
  "origin",
  "dnt",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-full-version-list",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
  "cloudfront-viewer-country",
  "cloudfront-viewer-country-region",
  "cloudfront-viewer-city",
  "cloudfront-viewer-asn",
  "cloudfront-viewer-time-zone",
  "cloudfront-viewer-tls",
  "cloudfront-viewer-http-version",
  "cloudfront-viewer-address",
  "cloudfront-is-mobile-viewer",
  "cloudfront-is-tablet-viewer",
  "cloudfront-is-desktop-viewer",
  "cloudfront-is-smarttv-viewer",
];

interface CapturedRequestHeaders {
  headers: Record<string, string>;
  /** Cookie *names* the client sent (values deliberately discarded). */
  cookie_names: string[];
}

function captureRequestHeaders(event: ExtendedEvent): CapturedRequestHeaders {
  const out: Record<string, string> = {};
  for (const name of CAPTURED_REQUEST_HEADER_NAMES) {
    const v = event.headers[name];
    if (typeof v === "string" && v.length > 0) out[name] = v;
  }
  // API GW V2 surfaces cookies as a separate array of raw "name=value" pairs,
  // not in the `headers` map. Pull the names only so we can show presence
  // without ever persisting values.
  const cookieNames = (event.cookies ?? [])
    .map((pair) => pair.split("=", 1)[0]?.trim())
    .filter((n): n is string => Boolean(n));
  return { headers: out, cookie_names: cookieNames };
}

function buildIntegrityItem(
  ctx: HandleContext,
  hydratedPayload: ArgusPayload,
  identity: IdentityOutcome,
) {
  const now = Date.now();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = ctx.payload as any;
  const clientIp = ctx.event.headers[XFF_HEADER]?.split(",")[0]?.trim() ?? "";
  const ua = ctx.event.headers[UA_HEADER] ?? "";

  const identification = buildIdentificationField(identity);
  const webrtcSigint = decodeWebrtcSigintCandidates(
    raw.device,
    process.env.SIGINT_AES_KEY,
  );
  const webrtcSigintField = buildWebrtcSigintField(webrtcSigint);
  const requestHeaders = captureRequestHeaders(ctx.event);

  return {
    session_id: ctx.sessionId,
    device: raw.device ?? {},
    meta: raw.meta ?? {},
    sigint: hydratedPayload.sigint ?? sigintSummary(ctx.payload),
    ...(identification ? { identification } : {}),
    analysis: {
      network: analyzeNetworkProbes(hydratedPayload.sigint),
      worker: analyzeWorkerScopes(raw.device),
      timezone: analyzeTimezone(raw.device, hydratedPayload.sigint),
      ip: analyzeIpConsistency(
        raw.device,
        hydratedPayload.sigint,
        clientIp,
        webrtcSigintEvidence(webrtcSigint),
      ),
      ja4_ua: analyzeJa4Ua(hydratedPayload.sigint, ua),
      ...(webrtcSigintField ? { webrtc_sigint: webrtcSigintField } : {}),
    },
    client_ip: clientIp,
    user_agent: ua,
    request_headers: requestHeaders,
    created_at: now,
    ttl: Math.floor(now / 1000) + INTEGRITY_TTL_SECONDS,
  };
}

async function handleIntegrity(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const hydratedPayload = await hydrateSigint(ctx.payload, ctx.deps, ctx.event);
  // Verify the client's device-identity sig against the raw (pre-hydration)
  // payload so sigintH2Token is still available. Failures never block —
  // the outcome is recorded on the row for analytics.
  const identity = await verifyDeviceIdentity(ctx.payload);
  emitIdentityMetrics(ctx.deps, identity);
  const item = buildIntegrityItem(ctx, hydratedPayload, identity);

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

  await maybeLearnSignalBaseline(ctx, hydratedPayload);

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

/**
 * Fire-and-forget: feed the session into the signal-learning baseline pipeline.
 * Errors are logged and metric-counted but never thrown — baseline learning
 * must not block or fail the integrity response.
 */
async function maybeLearnSignalBaseline(
  ctx: HandleContext,
  hydratedPayload: Awaited<ReturnType<typeof hydrateSigint>>,
): Promise<void> {
  if (!process.env.SIGNAL_BASELINES_TABLE) return;
  try {
    const {
      extractSignalObservation,
      passesDeterministicChecks,
      learnSignals,
    } = await import("../../services/signal-learning");
    const device = (ctx.payload as unknown as Record<string, unknown>).device;
    const observation = extractSignalObservation(
      device,
      hydratedPayload.sigint,
    );
    if (
      observation &&
      passesDeterministicChecks(device, hydratedPayload.sigint)
    ) {
      await learnSignals(observation);
      ctx.deps.metrics.addMetric("SignalLearningWritten", MetricUnit.Count, 1);
    }
  } catch (err) {
    ctx.deps.logger.warn("Signal learning failed", { error: err });
    ctx.deps.metrics.addMetric("SignalLearningError", MetricUnit.Count, 1);
  }
}
