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
import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { HttpError } from "../../helpers/http-error";
import { verifyDeviceMac } from "../../helpers/device-mac";
import {
  getSessionId,
  resolveCpi,
  type ArgusPayload,
} from "../../helpers/payload-schema";
import { CpiMerchantResolver } from "../../helpers/cpi-merchant-resolver";
import {
  verifyDeviceIdentity,
  type IdentityOutcome,
} from "../../helpers/device-identity";
import type { ProcessDeviceHistoryResult } from "../../helpers/device-history";
import { prewarmAsnDataset } from "../../services/network/asn-classifier";
import { prewarmAutoOverlay } from "../../services/network/auto-overlay";
import { prewarmAppleRelay } from "../../services/network/apple-relay";
import { prewarmBrowserBaselines } from "../../services/network/browser-baselines";
import { warmFirehose } from "../../helpers/firehose-archive";
import { getAwsSecrets } from "../../helpers/get-aws-secrets";
import { getValkey } from "../../helpers/valkey-client";
import { boundedRequestHandler } from "../../helpers/sdk-http-handler";
import { buildMerchantResponse } from "../../helpers/merchant-projection";
import { resolveIntegrityTtlSeconds } from "./ttl";
import { hydrateSigint } from "./sigint-hydration";
import {
  makePhaseTimer,
  phaseTimingEnabled,
  timeAsync,
  type PhaseTimer,
} from "../../helpers/phase-timer";
import { persistIntegrityRecord } from "./persist-integrity-record";
import { applyIpVelocitySnapshot, bumpIpVelocityBlocked } from "./ip-velocity";
import { runDeviceHistoryWorkflow } from "./device-history-workflow";
import { buildIntegrityRecord } from "./integrity-record-builder";

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
const integrityRecordPersistenceDeps = {
  dynamo: ddbClient,
  tableName: INTEGRITY_RESULTS_TABLE,
  firehoseStreamName: INTEGRITY_FIREHOSE_STREAM,
};
const ipVelocityEnrichmentDeps = { dynamo: ddbClient };

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

async function applyVelocityAndProjection(
  ctx: HandleContext,
  item: Record<string, unknown>,
  identity: IdentityOutcome,
): Promise<Record<string, unknown>> {
  const itemWithVelocity = await applyIpVelocitySnapshot({
    ctx,
    item,
    identity,
    deps: ipVelocityEnrichmentDeps,
  });
  const itemWithProjection = applyProjectionSnapshot(ctx, itemWithVelocity);
  await bumpIpVelocityBlocked({
    ctx,
    item: itemWithProjection,
    deps: ipVelocityEnrichmentDeps,
  });
  return itemWithProjection;
}

async function handleIntegrity(
  ctx: HandleContext,
): Promise<APIGatewayProxyResultV2> {
  const pt = makePhaseTimer();
  const hydratedPayload = await hydrateSigint(
    ctx.payload,
    ctx.deps,
    ctx.event,
    { dynamo: ddbClient, cpi: ctx.cpi },
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

  const { dh, analysis: deviceHistoryAnalysis } = runDeviceHistoryWorkflow({
    ctx,
    identity,
    sigintAesKey: process.env.SIGINT_AES_KEY,
  });
  pt.mark("device_history");

  const item = buildIntegrityRecord({
    ctx,
    hydratedPayload,
    identity,
    merchantId,
    deviceHistory: deviceHistoryAnalysis,
    sigintAesKey: process.env.SIGINT_AES_KEY,
    ttlSeconds: INTEGRITY_TTL_SECONDS,
  });
  pt.mark("analysis");

  // Velocity first so the projection-builder can pull ip_velocity_1h
  // into MerchantSafeResponse (with derived block_rate +
  // residential_proxy_suspect). Then bump blocked counter post-projection
  // once the verdict is known.
  const itemWithProjection = await applyVelocityAndProjection(
    ctx,
    item,
    identity,
  );
  pt.mark("velocity");

  const { duplicate } = await persistIntegrityRecord(
    ctx,
    itemWithProjection,
    integrityRecordPersistenceDeps,
  );
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
