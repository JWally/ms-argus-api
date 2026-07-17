/** Build the durable integrity row and enforce record-local trust boundaries. */
import type { Logger } from "@aws-lambda-powertools/logger";
import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { IdentityOutcome } from "../../helpers/device-identity";
import { HttpError } from "../../helpers/http-error";
import type { ArgusPayload } from "../../helpers/payload-schema";
import {
  buildWebrtcSigintField,
  decodeWebrtcSigintCandidates,
  type SigintCandidateDecodeResult,
} from "../../helpers/sigint-v6-decode";
import { claimStunNonce } from "../../helpers/stun-nonce-tracker";
import { lookupAppleRelaySync } from "../../services/network/apple-relay";
import {
  buildAnalysisBlock,
  buildIdentificationField,
  buildPatFields,
  captureRequestHeaders,
  sigintSummary,
} from "./integrity-analysis";

export interface IntegrityRecordContext {
  payload: ArgusPayload;
  sessionId: string;
  cpi: string;
  event: {
    headers: Record<string, string | undefined>;
    cookies?: string[];
  };
  deps: {
    logger: Pick<Logger, "warn">;
    metrics: Pick<Metrics, "addMetric">;
  };
}

interface BuildIntegrityRecordArgs {
  ctx: IntegrityRecordContext;
  hydratedPayload: ArgusPayload;
  identity: IdentityOutcome;
  merchantId: string | null;
  deviceHistory: DeviceHistoryAnalysis;
  sigintAesKey: string | undefined;
  ttlSeconds: number;
  now?: number;
}

function enforceStunCandidateSingleUse(
  result: SigintCandidateDecodeResult,
  ctx: IntegrityRecordContext,
): void {
  if (result.reason !== "ok" || !result.decoded) return;
  const claim = claimStunNonce(
    result.decoded.cipherB64,
    ctx.sessionId,
    ctx.cpi,
    result.decoded.ip,
  );
  if (claim.accepted) return;
  ctx.deps.metrics.addMetric("WebrtcStunReplay", MetricUnit.Count, 1);
  ctx.deps.logger.warn("WebRTC STUN candidate replay rejected", {
    session_id: ctx.sessionId,
    cpi: ctx.cpi,
    attested_ip: result.decoded.ip,
    first_claimed_by: claim.firstClaimedBy.sessionId,
    first_claimed_at: claim.firstClaimedBy.claimedAt,
  });
  throw new HttpError(409, "webrtc attestation already redeemed");
}

function appleRelayField(clientIp: string): { apple_relay_egress?: object } {
  const match = lookupAppleRelaySync(clientIp);
  return match ? { apple_relay_egress: match } : {};
}

export function buildIntegrityRecord(
  args: BuildIntegrityRecordArgs,
): Record<string, unknown> {
  const { ctx, hydratedPayload, identity, merchantId, deviceHistory } = args;
  const now = args.now ?? Date.now();
  const raw = ctx.payload as ArgusPayload & { meta?: unknown };
  const clientIp =
    ctx.event.headers["x-forwarded-for"]?.split(",")[0]?.trim() ?? "";
  const ua = ctx.event.headers["user-agent"] ?? "";
  const acceptLanguage = ctx.event.headers["accept-language"] ?? null;
  const identification = buildIdentificationField(identity);
  const webrtcSigint = decodeWebrtcSigintCandidates(
    raw.device,
    args.sigintAesKey,
  );
  enforceStunCandidateSingleUse(webrtcSigint, ctx);
  const webrtcSigintField = buildWebrtcSigintField(webrtcSigint);
  const requestHeaders = captureRequestHeaders(ctx.event);
  return {
    cpi: ctx.cpi,
    session_id: ctx.sessionId,
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
      requestHeaders: requestHeaders.headers,
      webrtcSigint,
      webrtcSigintField,
      deviceHistory,
    }),
    client_ip: clientIp,
    user_agent: ua,
    request_headers: requestHeaders,
    ...appleRelayField(clientIp),
    created_at: now,
    ttl: Math.floor(now / 1000) + args.ttlSeconds,
  };
}
