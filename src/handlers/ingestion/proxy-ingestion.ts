import { MetricUnit, type Metrics } from "@aws-lambda-powertools/metrics";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { APIGatewayProxyResultV2 } from "aws-lambda";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { IdentityOutcome } from "../../helpers/device-identity";
import type { ArgusPayload } from "../../helpers/payload-schema";
import {
  phaseTimingEnabled,
  timeAsync,
  type PhaseTimer,
} from "../../helpers/phase-timer";
import { prewarmAsnDataset } from "../../services/network/asn-classifier";
import { prewarmAutoOverlay } from "../../services/network/auto-overlay";
import { buildIntegrityRecord } from "./integrity-record-builder";

const PROXY_IDENTITY: IdentityOutcome = {
  present: false,
  verified: false,
  pubkey: null,
  sig_present: false,
  reason: "absent",
};

const PROXY_DEVICE_HISTORY: DeviceHistoryAnalysis = {
  tampered: false,
  identityMismatch: false,
  freshDevice: true,
  scanCount: 0,
  ageSeconds: 0,
  distinctIpCount: 0,
  distinctCountryCount: 0,
  distinctNetClassCount: 0,
  distinctCpiCount: 0,
  distinctUaCount: 0,
  recent5MinCount: 0,
  recent1HourCount: 0,
  recent24HourCount: 0,
};

interface ProxyContext {
  payload: ArgusPayload;
  sessionId: string;
  cpi: string;
  event: {
    headers: Record<string, string | undefined>;
    cookies?: string[];
  };
  deps: { logger: Logger; metrics: Metrics };
  start: number;
}

interface ProxyIngestionArgs {
  ctx: ProxyContext;
  hydratedPayload: ArgusPayload;
  phaseTimer: PhaseTimer;
  ttlSeconds: number;
  resolveMerchantId: () => Promise<string | null>;
  enrichAndProject: (
    item: Record<string, unknown>,
    identity: IdentityOutcome,
  ) => Promise<Record<string, unknown>>;
  persist: (item: Record<string, unknown>) => Promise<{ duplicate: boolean }>;
}

function stripFullProductAnalysis(
  item: Record<string, unknown>,
): Record<string, unknown> {
  const rawAnalysis = item.analysis;
  if (!rawAnalysis || typeof rawAnalysis !== "object") return item;
  const analysis = { ...(rawAnalysis as Record<string, unknown>) };
  delete analysis.device_history;
  return { ...item, analysis };
}

function buildResponse(sessionId: string): APIGatewayProxyResultV2 {
  return {
    statusCode: 200,
    body: JSON.stringify({ session_id: sessionId }),
    headers: { "Content-Type": "application/json" },
  };
}

/** Run the reduced-surface ingestion workflow after sigint token hydration. */
export async function handleProxyIntegrity(
  args: ProxyIngestionArgs,
): Promise<APIGatewayProxyResultV2> {
  const { ctx, hydratedPayload, phaseTimer: pt } = args;
  const [, , merchantId] = await Promise.all([
    timeAsync(pt, "id_asn", prewarmAsnDataset()),
    timeAsync(pt, "id_overlay", prewarmAutoOverlay()),
    timeAsync(pt, "id_merchant", args.resolveMerchantId()),
  ]);
  pt.mark("identity");

  const item = stripFullProductAnalysis(
    buildIntegrityRecord({
      ctx,
      hydratedPayload,
      identity: PROXY_IDENTITY,
      merchantId,
      deviceHistory: PROXY_DEVICE_HISTORY,
      sigintAesKey: process.env.SIGINT_AES_KEY,
      ttlSeconds: args.ttlSeconds,
    }),
  );
  pt.mark("analysis");

  const projected = await args.enrichAndProject(item, PROXY_IDENTITY);
  pt.mark("velocity");
  const { duplicate } = await args.persist(projected);
  pt.mark("persist");

  if (!duplicate) {
    ctx.deps.metrics.addMetric("ProxyIntegrityStored", MetricUnit.Count, 1);
  }
  ctx.deps.metrics.addMetric(
    "IntegrityDuration",
    MetricUnit.Milliseconds,
    Date.now() - ctx.start,
  );
  if (phaseTimingEnabled()) {
    ctx.deps.logger.info("phase_timing", pt.summary());
  }
  return buildResponse(ctx.sessionId);
}
