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
import {
  redeemSigintTokens,
  isAwsCfAuthenticallyHydrated,
} from "../../helpers/redeem-sigint-tokens";
import { claimStunNonce } from "../../helpers/stun-nonce-tracker";
import { redeemPatToken } from "../../helpers/redeem-pat-token";
import { CpiMerchantResolver } from "../../helpers/cpi-merchant-resolver";
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
  analyzeKernelOs,
  analyzeBrowserEngine,
  analyzeLocaleGeo,
  analyzeClientHintsUa,
  classifyProxy,
  type WebrtcSigintStatus,
} from "../../analysis";
import type { AsnCategory } from "../../analysis/ip-consistency/asn-catalog";
import { prewarmAsnDataset } from "../../services/network/asn-classifier";
import { prewarmAutoOverlay } from "../../services/network/auto-overlay";
import { prewarmBrowserBaselines } from "../../services/network/browser-baselines";
import { archiveToFirehose } from "../../helpers/firehose-archive";
import { resolveIntegrityTtlSeconds } from "./ttl";

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
const INTEGRITY_TTL_SECONDS = resolveIntegrityTtlSeconds(process.env);

// cpi → merchantId resolver. Lambda-scope so the cache lives across requests
// for the container's lifetime; the mapping is immutable per-cpi, so once
// resolved a cpi never needs another lookup. Absent env var (local dev /
// stages without the cross-stack wiring) → resolver is null and rows are
// written without `merchant_id`. Those rows won't surface in the dashboard's
// merchant-keyed listing, which is the correct fail-open behavior.
const MERCHANT_KEYS_TABLE = process.env.MERCHANT_KEYS_TABLE;
const cpiMerchantResolver = MERCHANT_KEYS_TABLE
  ? new CpiMerchantResolver({
      ddb: ddbClient,
      table: MERCHANT_KEYS_TABLE,
      indexName: process.env.MERCHANT_KEYS_CPI_INDEX,
    })
  : null;

export function createBaseHandler(deps: BaseHandlerDeps) {
  return async (event: ExtendedEvent): Promise<APIGatewayProxyResultV2> => {
    const start = Date.now();

    const earlyResponse = await routeRequest(event);
    if (earlyResponse) return earlyResponse;

    const payload = event.parsedBody as ArgusPayload;
    const sessionId = getSessionId(payload);
    if (!sessionId) {
      deps.metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
      throw new HttpError(
        400,
        "Missing or malformed session_id — set identifiers.session_id",
      );
    }
    // Header is the preferred source — see resolveCpi() docstring.
    const cpiHeader =
      event.headers?.["x-argus-cpi"] ?? event.headers?.["X-Argus-Cpi"];
    const cpi = resolveCpi(payload, cpiHeader);
    if (!cpi) {
      deps.metrics.addMetric("MissingCpi", MetricUnit.Count, 1);
      throw new HttpError(
        400,
        "Missing or malformed cpi — set x-argus-cpi header or identifiers.cpi",
      );
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

/**
 * Exported for unit testing of the catch arm — the "throw out of
 * redeemSigintTokens means refuse with 503, not silently fall back to
 * the original payload" semantic is structurally important and worth
 * direct coverage. Production callers use it via handleIntegrity
 * unchanged.
 */
export async function hydrateSigint(
  payload: ArgusPayload,
  deps: BaseHandlerDeps,
  event: ExtendedEvent,
): Promise<ArgusPayload> {
  const sigintAesKey = process.env.SIGINT_AES_KEY;
  const probeTokensTable = process.env.PROBE_TOKENS_TABLE_NAME;
  if (!sigintAesKey || !probeTokensTable) return payload;

  let hydrated: ArgusPayload;
  try {
    hydrated = await redeemSigintTokens(payload, {
      sigintAesKeyHex: sigintAesKey,
      probeTokensTableName: probeTokensTable,
      dynamo: ddbClient,
      logger: deps.logger,
      fpidCookie: extractFpidCookie(event.cookies),
      requestSourceIp: event.requestContext.http.sourceIp,
    });
    deps.metrics.addMetric("IntegritySigintRedeemed", MetricUnit.Count, 1);
  } catch (err) {
    // Refuse the request rather than fall back to the *original* payload.
    // Returning `payload` here would silently restore the attacker-controlled
    // inline `sigint.tcp_probe` / `sigint.h2` / `sigint.aws_cf` blobs that
    // Layer-1 strips inside redeemSigintTokens. Layer-2's anyHydrated check
    // would then see those inline objects as "hydrated" and let the row
    // through. Any throw out of redeemSigintTokens (DDB throttle, AWS SDK
    // transient, unexpected crypto error) is therefore a structural reopen
    // of ARGUS_URGENT_FIXES finding #1. 503 is the right semantic: this is
    // server-side transient unavailability, not a client error, so retries
    // are appropriate.
    deps.logger.warn(
      "Sigint token redemption threw — refusing rather than green-lighting original payload",
      {
        error: err,
      },
    );
    deps.metrics.addMetric("SigintHydrationError", MetricUnit.Count, 1);
    throw new HttpError(503, "sigint verification temporarily unavailable");
  }

  // Layer 2: require at least one probe to redeem successfully. Combined
  // with Layer 1 (inline data cleared before redemption), zero hydrated
  // probes means the submission carries NO trustworthy network evidence:
  // every authoritative field was either absent, forged, replayed, or
  // mismatched-IP. A real SDK execution always redeems all three. Reject
  // here rather than write a row that will analyze as clean-by-omission.
  //
  // aws_cf is special: applyTlsJson writes it for any parseable sigintTls
  // (stamping tampered/expired flags when the SipHash sig fails). A bare
  // `!!sigint?.aws_cf` therefore accepts a record the server already
  // flagged as forged — fully-junk sigintTcp/H2 tokens + a forged
  // sigintTls would pass this gate and analyze SAFE via the
  // proxy_waterfall rule-8 (ratio:null) clean fallback. Consult the
  // flags via isAwsCfAuthenticallyHydrated so only a verified CF probe
  // counts. tcp_probe / h2 are set ONLY after HMAC verification in
  // redeem-sigint-tokens, so truthiness is sufficient there.
  const anyHydrated =
    !!hydrated.sigint?.tcp_probe ||
    !!hydrated.sigint?.h2 ||
    isAwsCfAuthenticallyHydrated(hydrated.sigint);
  if (!anyHydrated) {
    deps.metrics.addMetric("SigintRedeemAllFailed", MetricUnit.Count, 1);
    throw new HttpError(400, "sigint probe redemption failed");
  }

  // PAT redemption is independent of sigint probe redemption — its token
  // is self-contained (HMAC-signed at /v1/pat-attestation, verified inline
  // here), so it shares the AES key but no DB infra. Failure modes drop
  // the field silently inside redeemPatToken.
  return redeemPatToken(hydrated, {
    expectedSrcIp: event.requestContext.http.sourceIp,
    sigintAesKeyHex: sigintAesKey,
    logger: deps.logger,
  });
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

/**
 * Network-axis analyses (ip + network + proxy_waterfall). Pulled out of
 * `buildAnalysisBlock` to keep that function under the per-function line
 * cap. ip runs first so its asn.category can feed analyzeNetworkProbes'
 * VPN-category override.
 */
function runNetworkAnalyses(inputs: AnalysisInputs) {
  const { raw, hydratedPayload, clientIp, ua, webrtcSigint } = inputs;
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
  const proxyWaterfall = runProxyWaterfall(ip, hydratedPayload, webrtcSigint);
  return { ip, network, proxyWaterfall };
}

function buildAnalysisBlock(inputs: AnalysisInputs) {
  const {
    raw,
    hydratedPayload,
    ua,
    acceptLanguage,
    requestHeaders,
    webrtcSigintField,
  } = inputs;
  const { ip, network, proxyWaterfall } = runNetworkAnalyses(inputs);
  const ja4Ua = analyzeJa4Ua(
    hydratedPayload.sigint,
    ua,
    requestHeaders?.["sec-ch-ua"] ?? null,
  );
  return {
    network,
    worker: analyzeWorkerScopes(raw.device),
    timezone: analyzeTimezone(raw.device, hydratedPayload.sigint),
    ip,
    ja4_ua: ja4Ua,
    kernel_os: analyzeKernelOs(hydratedPayload.sigint, ja4Ua.ua_os),
    browser_engine: runBrowserEngineAnalysis(
      raw.device,
      hydratedPayload.sigint,
      ua,
      requestHeaders,
    ),
    locale_geo: analyzeLocaleGeo(
      raw.device,
      acceptLanguage,
      extractCfCountry(hydratedPayload.sigint),
    ),
    client_hints_ua: analyzeClientHintsUa(
      ua,
      requestHeaders,
      (hydratedPayload.sigint as { tcp_probe?: unknown } | undefined)
        ?.tcp_probe,
    ),
    proxy_waterfall: proxyWaterfall,
    ...(webrtcSigintField && { webrtc_sigint: webrtcSigintField }),
  };
}

/**
 * Compose the proxy-waterfall classifier inputs from the ip-analysis result
 * and decoded sigint. Pulled out to keep buildAnalysisBlock under the
 * per-function line cap.
 */
function runProxyWaterfall(
  ip: ReturnType<typeof analyzeIpConsistency>,
  hydratedPayload: ArgusPayload,
  webrtcSigint: SigintCandidateDecodeResult,
) {
  return classifyProxy({
    tcpIp: ip.ips.tcp,
    webrtcIp: ip.ips.webrtc,
    // Read reason from the decoder result, not the stored field —
    // buildWebrtcSigintField() omits the entire field when reason is
    // "no_candidates", so the stored status would be undefined.
    webrtcStatus: webrtcSigint.reason as WebrtcSigintStatus,
    rttRatio: extractRttRatio(hydratedPayload.sigint),
  });
}

function isIncognito(device: unknown): boolean {
  if (!device || typeof device !== "object") return false;
  const incog = (device as { incognito?: { isPrivate?: unknown } }).incognito;
  return incog?.isPrivate === true;
}

/**
 * Browser-engine consistency check: claimed (UA + sec-ch-ua + incognito)
 * vs observed engine-invariant fields, scored against per-version baselines
 * built daily by browser-baseline-builder. Cold-start safe — returns no
 * signal when baseline is missing.
 */
function runBrowserEngineAnalysis(
  device: unknown,
  sigint: unknown,
  ua: string,
  requestHeaders: Record<string, string> | null,
) {
  return analyzeBrowserEngine({
    device,
    sigint,
    ua,
    secChUa: requestHeaders?.["sec-ch-ua"] ?? null,
    incognito: isIncognito(device),
  });
}

function extractCfCountry(sigint: unknown): string | null {
  const cf = (sigint as { aws_cf?: { country?: unknown } } | undefined)?.aws_cf;
  const c = cf?.country;
  return typeof c === "string" && c.length > 0 ? c : null;
}

/**
 * Pull the PAT-related fields off the hydrated payload for persistence.
 * patToken is intentionally NOT persisted (sensitive even though
 * HMAC-signed). patDiag is forensic-only — JS-side observation of what
 * `fetch()` actually saw, used to debug the cross-origin OS handoff.
 */
function buildPatFields(hydratedPayload: ArgusPayload): {
  pat?: ArgusPayload["pat"];
  patDiag?: string;
} {
  const out: { pat?: ArgusPayload["pat"]; patDiag?: string } = {};
  if (hydratedPayload.pat) out.pat = hydratedPayload.pat;
  if (hydratedPayload.patDiag) out.patDiag = hydratedPayload.patDiag;
  return out;
}

/**
 * Single-use enforcement for STUN attestation candidates. The sigint
 * STUN server's HMAC binds (clientIPv4, epoch, nonce) — not session_id —
 * so a captured candidate is replayable across sessions for the 300s
 * freshness window unless the API enforces consume-on-use. See
 * stun-nonce-tracker for the (deliberate) multi-container caveat.
 *
 * No-op when no candidate decoded (`reason !== "ok"`); analyzer already
 * has contingencies for that path. Throws HttpError(409) on cross-session
 * reclaim — same shape as the existing session-replay block.
 */
function enforceStunCandidateSingleUse(
  webrtcSigint: SigintCandidateDecodeResult,
  ctx: HandleContext,
): void {
  if (webrtcSigint.reason !== "ok" || !webrtcSigint.decoded) return;
  const claim = claimStunNonce(
    webrtcSigint.decoded.cipherB64,
    ctx.sessionId,
    ctx.cpi,
    webrtcSigint.decoded.ip,
  );
  if (claim.accepted) return;
  ctx.deps.metrics.addMetric("WebrtcStunReplay", MetricUnit.Count, 1);
  ctx.deps.logger.warn("WebRTC STUN candidate replay rejected", {
    session_id: ctx.sessionId,
    cpi: ctx.cpi,
    attested_ip: webrtcSigint.decoded.ip,
    first_claimed_by: claim.firstClaimedBy.sessionId,
    first_claimed_at: claim.firstClaimedBy.claimedAt,
  });
  throw new HttpError(409, "webrtc attestation already redeemed");
}

function buildIntegrityItem(
  ctx: HandleContext,
  hydratedPayload: ArgusPayload,
  identity: IdentityOutcome,
  merchantId: string | null,
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
  enforceStunCandidateSingleUse(webrtcSigint, ctx);
  const webrtcSigintField = buildWebrtcSigintField(webrtcSigint);
  const requestHeaders = captureRequestHeaders(ctx.event);

  return {
    cpi: ctx.cpi,
    session_id: ctx.sessionId,
    // Sparse GSI key: omitted when the resolver couldn't map cpi → merchantId
    // (unknown cpi, MERCHANT_KEYS_TABLE unset, etc.). DDB excludes rows
    // without the key from the merchantId-createdAt-index, which is the
    // correct behavior — we don't pollute someone else's merchant listing
    // with an unowned row.
    ...(merchantId ? { merchant_id: merchantId } : {}),
    device: raw.device ?? {},
    meta: raw.meta ?? {},
    sigint: hydratedPayload.sigint ?? sigintSummary(ctx.payload),
    ...(identification ? { identification } : {}),
    ...buildPatFields(hydratedPayload),
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

/**
 * Resolve merchantId for the row via the cpi-keyed resolver cache. Never
 * throws — a failed lookup yields null and the row is written without the
 * GSI key (sparse). Cache hit is free; cache miss is one Query on the
 * platform's merchant-keys cpi-index.
 */
async function resolveMerchantId(ctx: HandleContext): Promise<string | null> {
  if (!cpiMerchantResolver) return null;
  try {
    return await cpiMerchantResolver.resolve(ctx.cpi);
  } catch (err) {
    ctx.deps.logger.warn(
      "cpi → merchantId lookup failed; writing row without merchant_id",
      {
        cpi: ctx.cpi,
        error: (err as Error).message,
      },
    );
    ctx.deps.metrics.addMetric("MerchantIdResolveFailed", MetricUnit.Count, 1);
    return null;
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
  const [identity, merchantId] = await Promise.all([
    verifyDeviceIdentity(ctx.payload),
    resolveMerchantId(ctx),
    prewarmAsnDataset().catch((err) => {
      ctx.deps.logger.warn("ASN dataset prewarm failed", { error: err });
    }),
    prewarmAutoOverlay().catch((err) => {
      ctx.deps.logger.warn("Auto-overlay prewarm failed", { error: err });
    }),
    prewarmBrowserBaselines().catch((err) => {
      ctx.deps.logger.warn("Browser baselines prewarm failed", { error: err });
    }),
  ]);
  emitIdentityMetrics(ctx.deps, identity);
  const item = buildIntegrityItem(ctx, hydratedPayload, identity, merchantId);

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
