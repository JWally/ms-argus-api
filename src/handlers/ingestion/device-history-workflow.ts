import { MetricUnit } from "@aws-lambda-powertools/metrics";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import {
  computeDeviceHistoryAnalysis,
  type DeviceHistoryAnalysis,
} from "../../analysis/device-history";
import type { IdentityOutcome } from "../../helpers/device-identity";
import {
  hashUserAgent,
  processDeviceHistory,
  type DeviceHistoryBlob,
  type PendingVisit,
  type ProcessDeviceHistoryResult,
} from "../../helpers/device-history";
import type { ArgusPayload } from "../../helpers/payload-schema";
import { classifyAsnSync } from "../../services/network/asn-classifier";

const UA_HEADER = "user-agent";

export interface DeviceHistoryWorkflowContext {
  payload: ArgusPayload;
  cpi: string;
  sessionId: string;
  event: {
    headers: Record<string, string | undefined>;
    requestContext: { http: { sourceIp: string } };
  };
  deps: { metrics: Metrics };
}

interface RunDeviceHistoryWorkflowInput {
  ctx: DeviceHistoryWorkflowContext;
  identity: IdentityOutcome;
  sigintAesKey: string | undefined;
}

export interface DeviceHistoryWorkflowResult {
  dh: ProcessDeviceHistoryResult;
  analysis: DeviceHistoryAnalysis;
}

/** Build a server-observed visit from the integrity request. */
function buildPendingVisit(ctx: DeviceHistoryWorkflowContext): PendingVisit {
  const headers = ctx.event.headers;
  const latitude = parseFloat(headers["cloudfront-viewer-latitude"] ?? "");
  const longitude = parseFloat(headers["cloudfront-viewer-longitude"] ?? "");
  const cfAsn = headers["cloudfront-viewer-asn"];
  const asn = cfAsn ? parseInt(cfAsn, 10) : NaN;
  return {
    cpi: ctx.cpi,
    session: ctx.sessionId,
    ip: ctx.event.requestContext.http.sourceIp,
    ua_hash: hashUserAgent(headers[UA_HEADER]),
    net_class: Number.isFinite(asn) ? classifyAsnSync(asn) : null,
    country: headers["cloudfront-viewer-country"]?.toUpperCase() ?? null,
    region: headers["cloudfront-viewer-country-region"] ?? null,
    city: headers["cloudfront-viewer-city"] ?? null,
    lat: Number.isFinite(latitude) ? latitude : null,
    lon: Number.isFinite(longitude) ? longitude : null,
  };
}

function analysisOutcome(
  dh: ProcessDeviceHistoryResult,
):
  | { kind: "ok"; blob: DeviceHistoryBlob }
  | { kind: "absent" }
  | { kind: "auth_fail" } {
  if (dh.outcomeKind === "ok" && dh.identityMatched && dh.preVisitBlob) {
    return { kind: "ok", blob: dh.preVisitBlob };
  }
  if (dh.outcomeKind === "auth_fail") return { kind: "auth_fail" };
  return { kind: "absent" };
}

function emitDeviceHistoryMetric(
  metrics: Metrics,
  dh: ProcessDeviceHistoryResult,
): void {
  if (dh.outcomeKind === "auth_fail") {
    metrics.addMetric("DeviceHistoryAuthFail", MetricUnit.Count, 1);
  } else if (dh.outcomeKind === "absent") {
    metrics.addMetric("DeviceHistoryAbsent", MetricUnit.Count, 1);
  } else if (!dh.identityMatched) {
    metrics.addMetric("DeviceHistoryIdentityMismatch", MetricUnit.Count, 1);
  } else {
    metrics.addMetric("DeviceHistoryRoundtrip", MetricUnit.Count, 1);
  }
}

/**
 * Process the encrypted device-history cache, analyze its pre-visit state,
 * and meter the exact round-trip outcome. Identity mismatches deliberately
 * analyze as absent because the non-matching blob is discarded before use.
 */
export function runDeviceHistoryWorkflow(
  input: RunDeviceHistoryWorkflowInput,
): DeviceHistoryWorkflowResult {
  const { ctx, identity, sigintAesKey } = input;
  const dh = processDeviceHistory({
    incomingBlob: ctx.payload.cache,
    pubkey: identity.pubkey,
    sigintAesKey,
    visit: buildPendingVisit(ctx),
  });
  const analysis = computeDeviceHistoryAnalysis({
    outcome: analysisOutcome(dh),
    pubkey: identity.pubkey,
  });
  emitDeviceHistoryMetric(ctx.deps.metrics, dh);
  return { dh, analysis };
}
