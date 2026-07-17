/** Compose the server-owned analysis block and safe request evidence. */
import type { IdentityOutcome } from "../../helpers/device-identity";
import type { ArgusPayload } from "../../helpers/payload-schema";
import {
  buildWebrtcSigintField,
  type SigintCandidateDecodeResult,
} from "../../helpers/sigint-v6-decode";
import {
  analyzeBrowserEngine,
  analyzeClientHintsUa,
  analyzeIpConsistency,
  analyzeJa4Ua,
  analyzeKernelOs,
  analyzeLocaleGeo,
  analyzeNetworkProbes,
  analyzeTimezone,
  analyzeWorkerScopes,
  classifyProxy,
  type WebrtcSigintStatus,
} from "../../analysis";
import type { DeviceHistoryAnalysis } from "../../analysis/device-history";
import type { AsnCategory } from "../../analysis/ip-consistency/asn-catalog";

export function sigintSummary(payload: ArgusPayload): Record<string, string> {
  const present = (value: unknown) => (value ? "present" : "absent");
  return {
    tls: present(payload.sigintTls),
    tcp_token: present(payload.sigintTcpToken),
    h2_token: present(payload.sigintH2Token),
  };
}

export function buildIdentificationField(
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
  const fingerprint = tcp?.rtt_fingerprint as
    | Record<string, unknown>
    | undefined;
  const rtt =
    typeof fingerprint?.rtt_refreshed === "number"
      ? fingerprint.rtt_refreshed
      : undefined;
  const receivedRtt =
    typeof fingerprint?.rcv_rtt_refreshed === "number"
      ? fingerprint.rcv_rtt_refreshed
      : undefined;
  if (!rtt || rtt <= 0 || !receivedRtt || receivedRtt <= 0) return null;
  return receivedRtt / rtt;
}

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

export interface CapturedRequestHeaders {
  headers: Record<string, string>;
  /** Cookie names only; values are deliberately discarded. */
  cookie_names: string[];
}

interface HeaderEvent {
  headers: Record<string, string | undefined>;
  cookies?: string[];
}

export function captureRequestHeaders(
  event: HeaderEvent,
): CapturedRequestHeaders {
  const headers: Record<string, string> = {};
  for (const name of CAPTURED_REQUEST_HEADER_NAMES) {
    const value = event.headers[name];
    if (typeof value === "string" && value.length > 0) headers[name] = value;
  }
  const cookieNames = (event.cookies ?? [])
    .map((pair) => pair.split("=", 1)[0]?.trim())
    .filter((name): name is string => Boolean(name));
  return { headers, cookie_names: cookieNames };
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
  deviceHistory: DeviceHistoryAnalysis;
}

function runNetworkAnalyses(inputs: AnalysisInputs) {
  const { raw, hydratedPayload, clientIp, ua, webrtcSigint } = inputs;
  const ip = analyzeIpConsistency(
    raw.device,
    hydratedPayload.sigint,
    clientIp,
    webrtcSigintEvidence(webrtcSigint),
    ua,
  );
  return {
    ip,
    network: analyzeNetworkProbes(
      hydratedPayload.sigint,
      ip.asn.category as AsnCategory | null,
    ),
    proxyWaterfall: classifyProxy({
      tcpIp: ip.ips.tcp,
      webrtcIp: ip.ips.webrtc,
      webrtcStatus: webrtcSigint.reason as WebrtcSigintStatus,
      rttRatio: extractRttRatio(hydratedPayload.sigint),
    }),
  };
}

function isIncognito(device: unknown): boolean {
  if (!device || typeof device !== "object") return false;
  return (
    (device as { incognito?: { isPrivate?: unknown } }).incognito?.isPrivate ===
    true
  );
}

function extractCfCountry(sigint: unknown): string | null {
  const country = (sigint as { aws_cf?: { country?: unknown } } | undefined)
    ?.aws_cf?.country;
  return typeof country === "string" && country.length > 0 ? country : null;
}

export function buildAnalysisBlock(inputs: AnalysisInputs) {
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
    browser_engine: analyzeBrowserEngine({
      device: raw.device,
      sigint: hydratedPayload.sigint,
      ua,
      secChUa: requestHeaders?.["sec-ch-ua"] ?? null,
      incognito: isIncognito(raw.device),
    }),
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

export function buildPatFields(hydratedPayload: ArgusPayload): {
  pat?: ArgusPayload["pat"];
  patAttempt?: ArgusPayload["patAttempt"];
  patDiag?: string;
} {
  const fields: {
    pat?: ArgusPayload["pat"];
    patAttempt?: ArgusPayload["patAttempt"];
    patDiag?: string;
  } = {};
  if (hydratedPayload.pat) fields.pat = hydratedPayload.pat;
  if (hydratedPayload.patAttempt)
    fields.patAttempt = hydratedPayload.patAttempt;
  if (hydratedPayload.patDiag) fields.patDiag = hydratedPayload.patDiag;
  return fields;
}
