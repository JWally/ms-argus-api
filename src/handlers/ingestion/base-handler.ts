/**
 * Base HTTP handler for the integrity collection endpoint.
 *
 * Handles routing + integrity-record storage for POST /v1/integrity-collect.
 * The older /v1/collect fingerprint pipeline (SQS → matching-worker) was
 * removed along with everything downstream of it.
 * @module
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  ConditionalCheckFailedException,
  DynamoDBClient,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import {
  getSessionId,
  resolveCpi,
  type ArgusPayload,
} from "../../helpers/payload-schema";
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
  analyzeLocaleGeo,
  analyzeClientHintsUa,
  classifyProxy,
  type WebrtcSigintStatus,
} from "../../analysis";
import type { AsnCategory } from "../../analysis/ip-consistency/asn-catalog";
import { prewarmAsnDataset } from "../../services/network/asn-classifier";
import { prewarmAutoOverlay } from "../../services/network/auto-overlay";
import { archiveToFirehose } from "../../helpers/firehose-archive";

/** API Gateway event extended with pre-parsed body from middleware. */
export interface ExtendedEvent extends APIGatewayProxyEventV2 {
  /** Validated and parsed Argus payload from middleware */
  parsedBody?: ArgusPayload;
}

/** Dependencies required for the base ingestion handler. */
export interface BaseHandlerDeps {
  /** Logger instance for structured logging */
  logger: Logger;
  /** Metrics client for CloudWatch metrics */
  metrics: Metrics;
}

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
  if (event.rawPath !== "/v1/integrity-collect") {
    throw new HttpError(404, "Not found");
  }
  return null;
}

const ddbClient = new DynamoDBClient({});
const INTEGRITY_RESULTS_TABLE = process.env.INTEGRITY_RESULTS_TABLE ?? "";
const INTEGRITY_FIREHOSE_STREAM = process.env.INTEGRITY_FIREHOSE_STREAM;
const INTEGRITY_TTL_SECONDS = 3600; // 1 hour

export function createBaseHandler(deps: BaseHandlerDeps) {
  return async (event: ExtendedEvent): Promise<APIGatewayProxyResultV2> => {
    const start = Date.now();

    const earlyResponse = await routeRequest(event);
    if (earlyResponse) return earlyResponse;

    const payload = event.parsedBody as ArgusPayload;
    const sessionId = getSessionId(payload);
    const stage = process.env.STAGE ?? "dev";
    // Header is the preferred source — see resolveCpi() docstring.
    const cpiHeader =
      event.headers?.["x-argus-cpi"] ?? event.headers?.["X-Argus-Cpi"];
    const { cpi, bound } = resolveCpi(payload, stage, cpiHeader);
    if (!bound) {
      // LEGACY_UNBOUND_INGEST: bump so we can dashboard the migration.
      deps.metrics.addMetric("LegacyUnboundIngest", MetricUnit.Count, 1);
    }
    return handleIntegrity({ payload, sessionId, cpi, event, deps, start });
  };
}

interface HandleContext {
  payload: ArgusPayload;
  sessionId: string;
  cpi: string;
  event: ExtendedEvent;
  deps: BaseHandlerDeps;
  start: number;
}

const UA_HEADER = "user-agent";
const XFF_HEADER = "x-forwarded-for";

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

function extractRttRatio(sigint: unknown): number | null {
  const tcp = (sigint as Record<string, unknown> | undefined)?.tcp_probe as
    | Record<string, unknown>
    | undefined;
  const fp = tcp?.rtt_fingerprint as Record<string, unknown> | undefined;
  const rtt =
    typeof fp?.rtt_refreshed === "number" ? fp.rtt_refreshed : undefined;
  const rcv =
    typeof fp?.rcv_rtt_refreshed === "number"
      ? fp.rcv_rtt_refreshed
      : undefined;
  if (!rtt || rtt <= 0 || !rcv || rcv <= 0) return null;
  return rcv / rtt;
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

interface AnalysisInputs {
  raw: { device?: unknown };
  hydratedPayload: ArgusPayload;
  clientIp: string;
  ua: string;
  acceptLanguage: string | null;
  requestHeaders: Record<string, string> | null;
  webrtcSigint: SigintCandidateDecodeResult;
  webrtcSigintField: ReturnType<typeof buildWebrtcSigintField>;
}

function buildAnalysisBlock(inputs: AnalysisInputs) {
  const {
    raw,
    hydratedPayload,
    clientIp,
    ua,
    acceptLanguage,
    requestHeaders,
    webrtcSigint,
    webrtcSigintField,
  } = inputs;
  // ip analysis runs first so its asn.category can feed the network
  // analyzer's VPN-category override.
  const ip = analyzeIpConsistency(
    raw.device,
    hydratedPayload.sigint,
    clientIp,
    webrtcSigintEvidence(webrtcSigint),
    ua,
  );
  const network = analyzeNetworkProbes(
    hydratedPayload.sigint,
    ip.asn.category as AsnCategory | null,
  );
  const proxyWaterfall = classifyProxy({
    tcpIp: ip.ips.tcp,
    webrtcIp: ip.ips.webrtc,
    // Read reason from the decoder result, not the stored field —
    // buildWebrtcSigintField() omits the entire field when reason is
    // "no_candidates", so the stored status would be undefined.
    webrtcStatus: webrtcSigint.reason as WebrtcSigintStatus,
    rttRatio: extractRttRatio(hydratedPayload.sigint),
  });
  const localeGeo = analyzeLocaleGeo(
    raw.device,
    acceptLanguage,
    extractCfCountry(hydratedPayload.sigint),
  );
  const clientHintsUa = analyzeClientHintsUa(
    ua,
    requestHeaders,
    (hydratedPayload.sigint as { tcp_probe?: unknown } | undefined)?.tcp_probe,
  );
  return {
    network,
    worker: analyzeWorkerScopes(raw.device),
    timezone: analyzeTimezone(raw.device, hydratedPayload.sigint),
    ip,
    ja4_ua: analyzeJa4Ua(hydratedPayload.sigint, ua),
    locale_geo: localeGeo,
    client_hints_ua: clientHintsUa,
    proxy_waterfall: proxyWaterfall,
    ...(webrtcSigintField ? { webrtc_sigint: webrtcSigintField } : {}),
  };
}

function extractCfCountry(sigint: unknown): string | null {
  const cf = (sigint as { aws_cf?: { country?: unknown } } | undefined)?.aws_cf;
  const c = cf?.country;
  return typeof c === "string" && c.length > 0 ? c : null;
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
  const acceptLanguage = ctx.event.headers["accept-language"] ?? null;

  const identification = buildIdentificationField(identity);
  const webrtcSigint = decodeWebrtcSigintCandidates(
    raw.device,
    process.env.SIGINT_AES_KEY,
  );
  const webrtcSigintField = buildWebrtcSigintField(webrtcSigint);
  const requestHeaders = captureRequestHeaders(ctx.event);

  return {
    cpi: ctx.cpi,
    session_id: ctx.sessionId,
    device: raw.device ?? {},
    meta: raw.meta ?? {},
    sigint: hydratedPayload.sigint ?? sigintSummary(ctx.payload),
    ...(identification ? { identification } : {}),
    analysis: buildAnalysisBlock({
      raw,
      hydratedPayload,
      clientIp,
      ua,
      acceptLanguage,
      requestHeaders: requestHeaders?.headers ?? null,
      webrtcSigint,
      webrtcSigintField,
    }),
    client_ip: clientIp,
    user_agent: ua,
    request_headers: requestHeaders,
    created_at: now,
    ttl: Math.floor(now / 1000) + INTEGRITY_TTL_SECONDS,
  };
}

/**
 * Dual-write the integrity record. DDB is required (its result drives the
 * HTTP response). Firehose archive runs in parallel and never throws —
 * errors are logged + metered inside the helper. Shadow mode: the existing
 * DDB-stream → integrity-archiver path keeps writing per-session JSON
 * until Firehose is validated.
 */
async function persistIntegrityRecord(
  ctx: HandleContext,
  item: Record<string, unknown>,
): Promise<void> {
  try {
    await Promise.all([
      ddbClient.send(
        new PutItemCommand({
          TableName: INTEGRITY_RESULTS_TABLE,
          Item: marshall(item, { removeUndefinedValues: true }),
          // Composite key is (cpi, session_id) — uniqueness enforced on the
          // partition key; the sort key alone wouldn't catch cross-cpi reuse
          // (which we don't want anyway, but defense in depth).
          ConditionExpression: "attribute_not_exists(cpi)",
        }),
      ),
      archiveToFirehose(item, {
        streamName: INTEGRITY_FIREHOSE_STREAM,
        logger: ctx.deps.logger,
        metrics: ctx.deps.metrics,
      }),
    ]);
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      ctx.deps.metrics.addMetric("IntegrityReplayBlocked", MetricUnit.Count, 1);
      throw new HttpError(409, "Session already processed");
    }
    ctx.deps.logger.error("Integrity DynamoDB write failed", {
      error: err,
      cpi: ctx.cpi,
      session_id: ctx.sessionId,
    });
    ctx.deps.metrics.addMetric("IntegrityWriteFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }
}

async function handleIntegrity(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const hydratedPayload = await hydrateSigint(ctx.payload, ctx.deps, ctx.event);
  // Verify the client's device-identity sig against the raw (pre-hydration)
  // payload so sigintH2Token is still available. Failures never block —
  // the outcome is recorded on the row for analytics.
  // Run identity verification and ASN-dataset prewarm in parallel — the
  // dataset is needed by analyzeIpConsistency below; on cold start it costs
  // ~50–100 ms (one S3 GET), warm calls are no-ops.
  const [identity] = await Promise.all([
    verifyDeviceIdentity(ctx.payload),
    prewarmAsnDataset().catch((err) => {
      ctx.deps.logger.warn("ASN dataset prewarm failed", { error: err });
    }),
    prewarmAutoOverlay().catch((err) => {
      ctx.deps.logger.warn("Auto-overlay prewarm failed", { error: err });
    }),
  ]);
  emitIdentityMetrics(ctx.deps, identity);
  const item = buildIntegrityItem(ctx, hydratedPayload, identity);

  await persistIntegrityRecord(ctx, item);

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
