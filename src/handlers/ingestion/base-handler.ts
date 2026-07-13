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
  DescribeTableCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import { verifyDeviceMac } from "../../helpers/device-mac";
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
import { computeDeviceHistoryAnalysis } from "../../analysis/device-history";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import {
  processDeviceHistory,
  hashUserAgent,
  type ProcessDeviceHistoryResult,
} from "../../helpers/device-history";
import type { AsnCategory } from "../../analysis/ip-consistency/asn-catalog";
import {
  prewarmAsnDataset,
  classifyAsnSync,
} from "../../services/network/asn-classifier";
import { prewarmAutoOverlay } from "../../services/network/auto-overlay";
import { prewarmAppleRelay } from "../../services/network/apple-relay";
import { prewarmBrowserBaselines } from "../../services/network/browser-baselines";
import {
  archiveToFirehose,
  warmFirehose,
} from "../../helpers/firehose-archive";
import { getAwsSecrets } from "../../helpers/get-aws-secrets";
import { getValkey } from "../../helpers/valkey-client";
import { boundedRequestHandler } from "../../helpers/sdk-http-handler";
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import { lookupAppleRelaySync } from "../../services/network/apple-relay";
import {
  updateIpVelocity,
  bumpVelocityBlocked,
  pickDeviceId,
  type IpVelocitySnapshot,
} from "../../helpers/ip-velocity";
import { resolveIntegrityTtlSeconds } from "./ttl";
import {
  makePhaseTimer,
  phaseTimingEnabled,
  timeAsync,
  type PhaseTimer,
} from "../../helpers/phase-timer";

/** Bump when merchant-projection.ts rules change in a way you want stamped on
 *  rows. Stored on the row so historical verdicts are traceable to the code
 *  that produced them. */
const PROJECTION_VERSION = "v2";

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

// Bounded timeouts (defense-in-depth): DDB is the critical-path write that
// gates the response, and is subject to the same stale-keep-alive-socket hang
// across container freezes. It stays warm (hit on every request), so it rarely
// bites — but a dead socket here would block the client. See sdk-http-handler.ts.
const ddbClient = new DynamoDBClient({
  requestHandler: boundedRequestHandler,
});
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

/**
 * Deep warmup for the integrity-collect path. Runs the @middy/warmup onWarmup
 * hook (post-deploy ping + the 1-minute heater rule), exercising the exact
 * client singletons the real request uses so their keep-alive sockets never go
 * stale across a PC container freeze (the ~7.5s dead-socket stall). Strictly
 * READ-ONLY — DescribeTable + DescribeDeliveryStream + secret preload — so
 * nothing is written and no integrity record is created. Never throws; the
 * @middy/warmup short-circuit returns before any request handling.
 */
export async function deepWarmup(): Promise<void> {
  // Dataset prewarms (S3 GET + gunzip of ASN / overlay / Apple-relay / browser
  // baselines). On a cold container the first real request used to pay ~8s
  // loading these (the identity-phase spike phase-timing exposed) — Apple alone
  // is ~7s of synchronous compile, which is WHY it's loaded here and NEVER on
  // the request path. Loading them in the warmup means a fresh PC container is
  // primed by the post-deploy ping / 60s heater before any real traffic.
  // allSettled below swallows individual failures.
  const tasks: Array<Promise<unknown>> = [
    getAwsSecrets(),
    warmFirehose(INTEGRITY_FIREHOSE_STREAM),
    prewarmAsnDataset(),
    prewarmAutoOverlay(),
    prewarmAppleRelay(),
    prewarmBrowserBaselines(),
  ];
  if (INTEGRITY_RESULTS_TABLE) {
    tasks.push(
      ddbClient.send(
        new DescribeTableCommand({ TableName: INTEGRITY_RESULTS_TABLE }),
      ),
    );
  }
  // Valkey (ioredis) is the hot-path dependency NOT covered by the SDK bounded
  // handler, and its stale socket is the integrity-collect hang. PING keeps the
  // keep-alive socket fresh; if it's already dead, the ping fails fast and
  // ioredis reconnects in the background so the next real request finds it
  // ready. Bounded + swallowed so a Valkey blip never fails the warm.
  if (process.env.USE_VALKEY_IP_VELOCITY === "true") {
    tasks.push(
      Promise.race([
        Promise.resolve().then(() => getValkey().ping()),
        new Promise((resolve) => setTimeout(resolve, 1500)),
      ]).catch(() => {}),
    );
  }
  // allSettled: a single downstream hiccup must not fail the warm (or, worse,
  // surface as a Lambda error on the scheduled invoke).
  await Promise.allSettled(tasks);
}

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
 * Validate that the sigint verification env is configured. Missing env
 * has the same Layer-1-bypass property as the catch arm below — if we
 * skip redeemSigintTokens we skip its inline-data strip and inline
 * attacker blobs would survive to Layer-2's anyHydrated check. Refuse
 * with 503 rather than fall back to the original payload. Distinct
 * metric (SigintNotConfigured) so ops can alert at zero threshold —
 * unlike SigintHydrationError, this should never be non-zero in a
 * healthy deployment.
 */
function requireSigintEnv(deps: BaseHandlerDeps): {
  sigintAesKey: string;
  probeTokensTable: string;
} {
  const sigintAesKey = process.env.SIGINT_AES_KEY;
  const probeTokensTable = process.env.PROBE_TOKENS_TABLE_NAME;
  if (sigintAesKey && probeTokensTable) {
    return { sigintAesKey, probeTokensTable };
  }
  deps.logger.error(
    "Sigint env not configured — refusing rather than green-lighting original payload",
    {
      sigintAesKeyPresent: !!sigintAesKey,
      probeTokensTablePresent: !!probeTokensTable,
    },
  );
  deps.metrics.addMetric("SigintNotConfigured", MetricUnit.Count, 1);
  throw new HttpError(503, "sigint verification not configured");
}

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
  cpi: string = payload.identifiers.cpi ?? "",
): Promise<ArgusPayload> {
  const { sigintAesKey, probeTokensTable } = requireSigintEnv(deps);

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
    expectedCpi: cpi,
    expectedSessionId: hydrated.identifiers.session_id,
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
  /** Recurrence/stability signals from the device-history blob. See
   *  helpers/device-history + analysis/device-history. */
  deviceHistory: DeviceHistoryAnalysis;
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
      raw.device,
    ),
    proxy_waterfall: proxyWaterfall,
    ...(webrtcSigintField && { webrtc_sigint: webrtcSigintField }),
    device_history: inputs.deviceHistory,
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
  patAttempt?: ArgusPayload["patAttempt"];
  patDiag?: string;
} {
  const out: {
    pat?: ArgusPayload["pat"];
    patAttempt?: ArgusPayload["patAttempt"];
    patDiag?: string;
  } = {};
  if (hydratedPayload.pat) out.pat = hydratedPayload.pat;
  if (hydratedPayload.patAttempt) out.patAttempt = hydratedPayload.patAttempt;
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

interface BuildIntegrityItemArgs {
  ctx: HandleContext;
  hydratedPayload: ArgusPayload;
  identity: IdentityOutcome;
  merchantId: string | null;
  deviceHistory: DeviceHistoryAnalysis;
}

function buildIntegrityItem(args: BuildIntegrityItemArgs) {
  const { ctx, hydratedPayload, identity, merchantId, deviceHistory } = args;
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
      deviceHistory,
    }),
    client_ip: clientIp,
    user_agent: ua,
    request_headers: requestHeaders,
    // Apple iCloud Private Relay egress check — Apple's published egress
    // CIDR list (mask-api.icloud.com) is ground truth for "real Apple
    // device." When present, the projection treats the row as
    // PAT-equivalent trust evidence and suppresses signals whose root
    // cause is the Fastly/Cloudflare/Akamai Linux egress terminator
    // (KERNEL_OS_MISMATCH_DARWIN, etc.). Field absent on non-match,
    // empty list, or pre-prewarm cold start.
    ...((): { apple_relay_egress?: object } => {
      const m = lookupAppleRelaySync(clientIp);
      return m ? { apple_relay_egress: m } : {};
    })(),
    created_at: now,
    ttl: Math.floor(now / 1000) + INTEGRITY_TTL_SECONDS,
  };
}

/**
 * Run the merchant-projection builder against the freshly-built row and
 * splice the snapshot onto the item. Readers (pair-api, dashboard) can read
 * the stored verdict instead of rebuilding from raw — kills version-drift
 * between writer and reader and saves the per-read cost of the builder.
 *
 * Fails open: if the builder throws (it shouldn't on a well-formed item),
 * we log and persist the row without the snapshot. Ingestion must not break
 * on a scoring bug.
 */
function applyProjectionSnapshot(
  ctx: HandleContext,
  item: Record<string, unknown>,
): Record<string, unknown> {
  try {
    const projection = buildMerchantResponse({
      session_id: ctx.sessionId,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      integrity: item as any,
    });
    return {
      ...item,
      merchant_projection: projection,
      projection_built_at: Date.now(),
      projection_version: PROJECTION_VERSION,
    };
  } catch (err) {
    ctx.deps.logger.warn(
      "projection snapshot failed; persisting row without it",
      {
        error: err,
        session_id: ctx.sessionId,
      },
    );
    return item;
  }
}

/**
 * Phase 1 of velocity wiring: hits + HLL update + stamp. Runs BEFORE
 * the projection so buildMerchantResponse can pull ip_velocity_1h into
 * MerchantSafeResponse. `blocked` counter is NOT incremented here —
 * verdict isn't known yet. bumpIpVelocityBlocked handles that
 * atomically after the projection. Non-fatal on any failure.
 */
async function applyIpVelocitySnapshot(
  ctx: HandleContext,
  item: Record<string, unknown>,
  identity: IdentityOutcome,
): Promise<Record<string, unknown>> {
  const ip = (item as { client_ip?: string }).client_ip;
  if (!ip) return item;
  const clientUuid =
    (ctx.payload as { device?: { client_uuid?: string } }).device
      ?.client_uuid ?? null;
  const deviceId = pickDeviceId(identity.pubkey, clientUuid);
  if (!deviceId) return item;
  try {
    // Hard deadline: IP-velocity is non-critical enrichment, and its Valkey
    // path (ioredis) is NOT covered by the SDK bounded handler — a stale
    // keep-alive socket across a PC freeze makes ioredis reconnect/retry stack
    // toward the 10s Lambda timeout (the intermittent integrity-collect hang).
    // Cap it and fail open fast: score without velocity rather than hang.
    const velocityPromise = updateIpVelocity({ ip, deviceId, ddb: ddbClient });
    // Mark handled so a late rejection (after the race times out) isn't an
    // unhandled rejection; a fast rejection still propagates to the catch below.
    velocityPromise.catch(() => {});
    const snap: IpVelocitySnapshot | null = await Promise.race([
      velocityPromise,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 1500)),
    ]);
    if (!snap) return item;
    return { ...item, ip_velocity_1h: snap };
  } catch (err) {
    ctx.deps.logger.warn(
      "ip-velocity snapshot failed; persisting row without it",
      {
        error: err,
        session_id: ctx.sessionId,
      },
    );
    return item;
  }
}

/**
 * Phase 2 of velocity wiring: atomic ADD blocked :1 on the velocity
 * bucket when the projection's verdict is "block". Non-fatal — verdicts
 * are never blocked by a failed velocity bump.
 */
async function bumpIpVelocityBlocked(
  ctx: HandleContext,
  item: Record<string, unknown>,
): Promise<void> {
  const proj = (item as { merchant_projection?: { verdict?: string } })
    .merchant_projection;
  if (proj?.verdict !== "block") return;
  const vel = (item as { ip_velocity_1h?: { ip?: string; bucket?: string } })
    .ip_velocity_1h;
  if (!vel?.ip || !vel?.bucket) return;
  try {
    await bumpVelocityBlocked({
      ip: vel.ip,
      bucket: vel.bucket,
      ddb: ddbClient,
    });
  } catch (err) {
    ctx.deps.logger.warn("ip-velocity blocked bump failed", {
      error: err,
      session_id: ctx.sessionId,
    });
  }
}

/**
 * Dual-write the integrity record. DDB is required (its result drives the
 * HTTP response). Firehose archive runs in parallel and never throws —
 * errors are logged + metered inside the helper. Shadow mode: the existing
 * DDB-stream → integrity-archiver path keeps writing per-session JSON
 * until Firehose is validated.
 *
 * Returns `{ duplicate }`. A `ConditionalCheckFailedException` means a row
 * already exists for this (cpi, session_id) — i.e. the SAME scan was already
 * processed under the SAME session_id. That is the idempotent-retry path,
 * NOT a distinct replay: the SDK mints one session_id per scan and shares it
 * across its worker submission and the in-iframe fallback submission (and
 * API Gateway / network layers may retry), so the second write is a
 * duplicate of an already-committed session. We surface `duplicate:true` and
 * let the caller return the same 200 response (the same session_id it already
 * holds) instead of a 409. This mirrors the STUN single-use claim, which
 * already accepts a same-session re-claim as idempotent
 * (`stun-nonce-tracker` `existing.sessionId === sessionId`). It is also safe
 * against a genuine replay attacker: they cannot mutate the committed row
 * (the condition still blocks the overwrite) and only get back the original
 * session's response.
 */
export async function persistIntegrityRecord(
  ctx: HandleContext,
  item: Record<string, unknown>,
): Promise<{ duplicate: boolean }> {
  // Firehose is best-effort archival. DynamoDB is the durable source of truth
  // and the only write that should hold the client response. Lambda may freeze
  // this work after the handler returns, so archive delivery is intentionally
  // not part of the integrity-collect success contract.
  void archiveToFirehose(item, {
    streamName: INTEGRITY_FIREHOSE_STREAM,
    logger: ctx.deps.logger,
    metrics: ctx.deps.metrics,
  }).catch(() => {});

  try {
    await ddbClient.send(
      new PutItemCommand({
        TableName: INTEGRITY_RESULTS_TABLE,
        Item: marshall(item, { removeUndefinedValues: true }),
        // Composite key is (cpi, session_id) — uniqueness enforced on the
        // partition key; the sort key alone wouldn't catch cross-cpi reuse
        // (which we don't want anyway, but defense in depth).
        ConditionExpression: "attribute_not_exists(cpi)",
      }),
    );
    return { duplicate: false };
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      // Idempotent same-session retry — see docstring. Not an error.
      ctx.deps.metrics.addMetric(
        "IntegrityIdempotentRetry",
        MetricUnit.Count,
        1,
      );
      ctx.deps.logger.info(
        "integrity same-session retry — returning existing session",
        { cpi: ctx.cpi, session_id: ctx.sessionId },
      );
      return { duplicate: true };
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

/**
 * Phase 2 device-history round-trip. Decrypts the incoming blob (if any),
 * computes recurrence signals from pre-visit state, appends the current
 * submission as a fresh visit, re-encrypts. Returns the pre-visit signals
 * for the row's analysis.device_history block and the encrypted outbound
 * blob for the response.
 */
/**
 * Build the PendingVisit shape from request-time data. CloudFront
 * viewer-* headers are present on every request (country, region, city,
 * latitude, longitude, asn) — no analyzer needed. net_class is derived
 * from `cloudfront-viewer-asn` through the prewarmed ASN classifier
 * (microseconds). lat/lon arrive as string-encoded floats; NaN on
 * absence or malformed input maps to null.
 */
function buildPendingVisit(
  ctx: HandleContext,
): import("../../helpers/device-history").PendingVisit {
  const h = ctx.event.headers;
  const lat = parseFloat(h["cloudfront-viewer-latitude"] ?? "");
  const lon = parseFloat(h["cloudfront-viewer-longitude"] ?? "");
  const cfAsn = h["cloudfront-viewer-asn"];
  const asnNum = cfAsn ? parseInt(cfAsn, 10) : NaN;
  return {
    cpi: ctx.cpi,
    session: ctx.sessionId,
    ip: ctx.event.requestContext.http.sourceIp,
    ua_hash: hashUserAgent(h[UA_HEADER]),
    net_class: Number.isFinite(asnNum) ? classifyAsnSync(asnNum) : null,
    country: h["cloudfront-viewer-country"]?.toUpperCase() ?? null,
    region: h["cloudfront-viewer-country-region"] ?? null,
    city: h["cloudfront-viewer-city"] ?? null,
    lat: Number.isFinite(lat) ? lat : null,
    lon: Number.isFinite(lon) ? lon : null,
  };
}

function runDeviceHistory(
  ctx: HandleContext,
  identity: IdentityOutcome,
): {
  dh: ProcessDeviceHistoryResult;
  analysis: DeviceHistoryAnalysis;
} {
  const dh = processDeviceHistory({
    incomingBlob: ctx.payload.cache,
    pubkey: identity.pubkey,
    sigintAesKey: process.env.SIGINT_AES_KEY,
    visit: buildPendingVisit(ctx),
  });
  // Discriminate on the round-trip outcome, NOT on preVisitBlob (which
  // processDeviceHistory always populates with a fresh-for-this-pubkey
  // blob on the absent / auth_fail / identity-mismatch paths so it can
  // still record the current visit). The analyzer needs the original
  // outcome so freshDevice / tampered signals actually light up.
  let analyzerOutcome:
    | { kind: "ok"; blob: typeof dh.preVisitBlob & object }
    | { kind: "absent" }
    | { kind: "auth_fail" };
  if (dh.outcomeKind === "ok" && dh.identityMatched && dh.preVisitBlob) {
    analyzerOutcome = { kind: "ok", blob: dh.preVisitBlob };
  } else if (dh.outcomeKind === "auth_fail") {
    analyzerOutcome = { kind: "auth_fail" };
  } else {
    // absent OR identity-mismatch-on-ok-decrypt — both are honest
    // "no history for this pubkey" cases. The analyzer already
    // distinguishes mismatch via the pubkey check below, but we
    // already discarded the non-matching blob in processDeviceHistory.
    analyzerOutcome = { kind: "absent" };
  }
  const analysis = computeDeviceHistoryAnalysis({
    outcome: analyzerOutcome,
    pubkey: identity.pubkey,
  });
  emitDeviceHistoryMetrics(ctx.deps, dh);
  return { dh, analysis };
}

/**
 * Verify the SDK's device.mac chain (HMAC-MD5 over the device slices,
 * keyed by session-bound material — see helpers/device-mac.ts and the
 * ms-argus-web-integrity defense/hmac-chain branch). Three outcomes:
 *   - 'absent'   → old cached SDK bundle without device.mac. Skip
 *                  (rollout grace window so cached clients keep working).
 *   - 'ok'       → payload integrity confirmed. Proceed.
 *   - 'mismatch' → cleartext was tampered between SDK collection and
 *                  the wire. Hard reject with HttpError(400).
 */
function enforceDeviceMac(ctx: HandleContext): void {
  const sessionToken =
    ctx.event.headers["x-argus-session"] ??
    ctx.event.headers["X-Argus-Session"] ??
    "";
  const macOutcome = verifyDeviceMac(ctx.payload, { sessionToken });
  if (macOutcome.kind === "mismatch") {
    ctx.deps.metrics.addMetric("DeviceMacMismatch", MetricUnit.Count, 1);
    ctx.deps.logger.warn("device.mac mismatch — rejecting", {
      cpi: ctx.cpi,
      session_id: ctx.sessionId,
      expected_prefix: macOutcome.expected.slice(0, 16),
      received_prefix: macOutcome.received.slice(0, 16),
    });
    throw new HttpError(400, "device_mac_mismatch");
  }
  if (macOutcome.kind === "absent") {
    ctx.deps.metrics.addMetric("DeviceMacAbsent", MetricUnit.Count, 1);
  } else {
    ctx.deps.metrics.addMetric("DeviceMacOk", MetricUnit.Count, 1);
  }
}

/**
 * Verify device identity + resolve merchant, while prewarming the datasets the
 * analyzer needs downstream (ASN / auto-overlay / browser baselines) in one
 * Promise.all. Each branch is phase-timed (id_verify / id_merchant / id_asn /
 * id_overlay / id_baselines).
 *
 * Apple Relay is deliberately NOT prewarmed here. Loading it is ~7s of
 * SYNCHRONOUS CPU (gunzip + JSON.parse ~10MB + compiling Apple's 287k-CIDR
 * list), which freezes Node's single event loop — even fired with `void` it
 * stalls whatever await is in flight (we watched the 7s jump from id_apple to
 * id_asn). It's loaded ONLY by deepWarmup (heater / post-deploy ping, on their
 * own invocations); a request finds it cached or degrades to "not relay" (the
 * lookup fails open to the JA4 heuristic) but never runs the compile on-thread.
 */
function loadIdentityAndPrewarm(ctx: HandleContext, pt: PhaseTimer) {
  return Promise.all([
    timeAsync(pt, "id_verify", verifyDeviceIdentity(ctx.payload)),
    timeAsync(pt, "id_merchant", resolveMerchantId(ctx)),
    timeAsync(
      pt,
      "id_asn",
      prewarmAsnDataset().catch((err) => {
        ctx.deps.logger.warn("ASN dataset prewarm failed", { error: err });
      }),
    ),
    timeAsync(
      pt,
      "id_overlay",
      prewarmAutoOverlay().catch((err) => {
        ctx.deps.logger.warn("Auto-overlay prewarm failed", { error: err });
      }),
    ),
    timeAsync(
      pt,
      "id_baselines",
      prewarmBrowserBaselines().catch((err) => {
        ctx.deps.logger.warn("Browser baselines prewarm failed", {
          error: err,
        });
      }),
    ),
  ]);
}

async function handleIntegrity(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const pt = makePhaseTimer();
  const hydratedPayload = await hydrateSigint(
    ctx.payload,
    ctx.deps,
    ctx.event,
    ctx.cpi,
  );
  pt.mark("hydrate");
  enforceDeviceMac(ctx);
  // Verify the client's device-identity sig against the raw (pre-hydration)
  // payload so sigintH2Token is still available; failures never block (the
  // outcome is recorded for analytics). This also prewarms the analyzer's
  // datasets in the same Promise.all — see loadIdentityAndPrewarm for why
  // Apple Relay is excluded from the request path.
  const [identity, merchantId] = await loadIdentityAndPrewarm(ctx, pt);
  emitIdentityMetrics(ctx.deps, identity);
  pt.mark("identity");

  const { dh, analysis: deviceHistoryAnalysis } = runDeviceHistory(
    ctx,
    identity,
  );
  pt.mark("device_history");

  const item = buildIntegrityItem({
    ctx,
    hydratedPayload,
    identity,
    merchantId,
    deviceHistory: deviceHistoryAnalysis,
  });
  pt.mark("analysis");

  // Velocity first so the projection-builder can pull ip_velocity_1h
  // into MerchantSafeResponse (with derived block_rate +
  // residential_proxy_suspect). Then bump blocked counter post-projection
  // once the verdict is known.
  const itemWithVelocity = await applyIpVelocitySnapshot(ctx, item, identity);
  const itemWithProjection = applyProjectionSnapshot(ctx, itemWithVelocity);
  await bumpIpVelocityBlocked(ctx, itemWithProjection);
  pt.mark("velocity");

  const { duplicate } = await persistIntegrityRecord(ctx, itemWithProjection);
  pt.mark("persist");

  emitIngestMetricsAndReturn(ctx, dh, duplicate);
  if (phaseTimingEnabled()) {
    ctx.deps.logger.info("phase_timing", pt.summary());
  }
  return buildIntegrityResponse(ctx.sessionId, dh.outboundBlob);
}

function emitIngestMetricsAndReturn(
  ctx: HandleContext,
  dh: ProcessDeviceHistoryResult,
  duplicate: boolean,
): void {
  // Only count a fresh write as "stored"; an idempotent same-session retry
  // is metered separately in persistIntegrityRecord (IntegrityIdempotentRetry).
  if (!duplicate) {
    ctx.deps.metrics.addMetric("IntegrityStored", MetricUnit.Count, 1);
  }
  ctx.deps.metrics.addMetric(
    "IntegrityDuration",
    MetricUnit.Milliseconds,
    Date.now() - ctx.start,
  );
  void dh;
}

function buildIntegrityResponse(
  sessionId: string,
  outboundBlob: string | undefined,
): APIGatewayProxyResultV2 {
  return {
    statusCode: 200,
    body: JSON.stringify({
      session_id: sessionId,
      ...(outboundBlob ? { cache: outboundBlob } : {}),
    }),
    headers: { "Content-Type": "application/json" },
  };
}

/**
 * Emit metrics for the device-history round-trip outcome. tampered /
 * identity_mismatch / fresh distinct counts so ops can see the
 * distribution post-deploy.
 */
function emitDeviceHistoryMetrics(
  deps: BaseHandlerDeps,
  dh: ProcessDeviceHistoryResult,
): void {
  if (dh.outcomeKind === "auth_fail") {
    deps.metrics.addMetric("DeviceHistoryAuthFail", MetricUnit.Count, 1);
  } else if (dh.outcomeKind === "absent") {
    deps.metrics.addMetric("DeviceHistoryAbsent", MetricUnit.Count, 1);
  } else if (!dh.identityMatched) {
    deps.metrics.addMetric(
      "DeviceHistoryIdentityMismatch",
      MetricUnit.Count,
      1,
    );
  } else {
    deps.metrics.addMetric("DeviceHistoryRoundtrip", MetricUnit.Count, 1);
  }
}
