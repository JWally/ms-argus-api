import type { ArgusPayload } from "../../helpers/payload-schema";
import type { Fingerprint } from "../../types";

/**
 * Extract flat fingerprint fields from V3 payload.
 * Pure transformation: no AWS calls, no side effects.
 */
export function extractFingerprint(
  payload: ArgusPayload,
  headers?: Record<string, string>,
): Fingerprint {
  const { hashes, device, sigint, identifiers } = payload;

  const fingerprint: Fingerprint = {
    stable_hash: hashes.stable,
    fuzzy_hash: hashes.fuzzy,
  };

  extractIdentifiers(identifiers, fingerprint);
  extractWorkerScope(device, fingerprint);
  extractGpuFallback(device, fingerprint);
  extractScreen(device, fingerprint);
  extractHashes(hashes, fingerprint);
  extractWebglExtensions(device, fingerprint);
  extractSigint(sigint, fingerprint);
  extractIpFallback(headers, fingerprint);
  extractPrivacySignals(device, fingerprint);
  extractBotSignals(device, fingerprint);

  return fingerprint;
}

function extractIdentifiers(
  identifiers: ArgusPayload["identifiers"],
  fp: Fingerprint,
) {
  if (identifiers.evercookie_id) fp.evercookie_id = identifiers.evercookie_id;
  if (identifiers.public_key) fp.public_key = identifiers.public_key;
}

function extractWorkerScope(device: ArgusPayload["device"], fp: Fingerprint) {
  const workerScope = device.workerScope;
  if (!workerScope) return;

  if (typeof workerScope.userAgent === "string")
    fp.user_agent = workerScope.userAgent;
  if (typeof workerScope.hardwareConcurrency === "number")
    fp.hardware_concurrency = workerScope.hardwareConcurrency;
  if (typeof workerScope.deviceMemory === "number")
    fp.device_memory = workerScope.deviceMemory;
  if (typeof workerScope.webglRenderer === "string")
    fp.gpu_renderer = workerScope.webglRenderer;
  if (typeof workerScope.timezoneLocation === "string")
    fp.timezone = workerScope.timezoneLocation;
}

function extractGpuFallback(device: ArgusPayload["device"], fp: Fingerprint) {
  if (fp.gpu_renderer) return;
  const gpu = device.canvasWebgl?.gpu as Record<string, unknown> | undefined;
  if (gpu?.compressedGPU && typeof gpu.compressedGPU === "string") {
    fp.gpu_renderer = gpu.compressedGPU;
  }
}

function extractScreen(device: ArgusPayload["device"], fp: Fingerprint) {
  const screen = device.screen;
  if (!screen) return;
  const { width, height } = screen;
  if (typeof width === "number" && typeof height === "number") {
    fp.screen_dims = `${width}x${height}`;
  }
}

const HASH_FIELD_MAP: [keyof ArgusPayload["hashes"], keyof Fingerprint][] = [
  ["canvas2d", "canvas_hash"],
  ["canvasWebgl", "webgl_hash"],
  ["offlineAudioContext", "audio_hash"],
  ["maths", "maths_hash"],
  ["windowFeatures", "window_features_hash"],
  ["htmlElementVersion", "html_element_hash"],
  ["css", "css_hash"],
  ["svg", "svg_hash"],
  ["intl", "intl_hash"],
  ["features", "features_hash"],
  ["consoleErrors", "console_errors_hash"],
  ["clientRects", "client_rects_hash"],
];

function extractHashes(hashes: ArgusPayload["hashes"], fp: Fingerprint) {
  for (const [src, dst] of HASH_FIELD_MAP) {
    if (hashes[src]) (fp as Record<string, unknown>)[dst] = hashes[src];
  }
}

function extractWebglExtensions(
  device: ArgusPayload["device"],
  fp: Fingerprint,
) {
  const webglData = device.canvasWebgl;
  if (webglData && Array.isArray(webglData.extensions)) {
    fp.webgl_extensions_count = (webglData.extensions as unknown[]).length;
  }
}

function extractTlsFields(
  tls: NonNullable<ArgusPayload["sigint"]>["tlsFingerprint"],
  fp: Fingerprint,
) {
  if (!tls) return;
  if (tls.ip) fp.ip_address = tls.ip;
  if (tls.ja3) fp.ja3 = tls.ja3;
  if (tls.ja4) fp.ja4 = tls.ja4;
  if (tls.id) fp.sigint_id = tls.id;
}

function extractSigint(sigint: ArgusPayload["sigint"], fp: Fingerprint) {
  if (!sigint) return;
  extractTlsFields(sigint.tlsFingerprint, fp);
  extractTcpProbe(sigint, fp);
  if (sigint.faviconCache?.id) fp.favicon_cache_id = sigint.faviconCache.id;
  extractStun(sigint, fp);
}

function applyTcpFields(
  source: Record<string, unknown>,
  fp: Fingerprint,
  legacy: boolean,
) {
  const proxyKey = legacy ? "proxyScore" : "proxy_score";
  const vpnKey = legacy ? "vpnScore" : "vpn_score";
  const rttKey = legacy ? "rttMs" : "tcp_rtt_us";

  if (typeof source[proxyKey] === "number")
    fp.proxy_score = source[proxyKey] as number;
  if (typeof source[vpnKey] === "number")
    fp.vpn_score = source[vpnKey] as number;
  if (typeof source[rttKey] === "number") {
    fp.tcp_rtt_us = legacy
      ? (source[rttKey] as number) * 1000
      : (source[rttKey] as number);
  }
}

function extractTcpProbe(
  sigint: NonNullable<ArgusPayload["sigint"]>,
  fp: Fingerprint,
) {
  if (!sigint.tcpProbe) return;
  const tcp = sigint.tcpProbe as Record<string, unknown>;
  const rttFp = tcp.rtt_fingerprint as Record<string, unknown> | undefined;
  applyTcpFields(rttFp || tcp, fp, !rttFp);
}

function extractStun(
  sigint: NonNullable<ArgusPayload["sigint"]>,
  fp: Fingerprint,
) {
  const stun = sigint.stun as Record<string, unknown> | undefined;
  if (!stun) return;

  const publicIp = stun.publicIp ?? stun.reflexiveIp;
  if (typeof publicIp === "string") fp.stun_public_ip = publicIp;

  const localIp = stun.localIp ?? (stun.localIps as string[] | undefined)?.[0];
  if (typeof localIp === "string") fp.stun_local_ip = localIp;
}

function extractIpFallback(
  headers: Record<string, string> | undefined,
  fp: Fingerprint,
) {
  if (fp.ip_address || !headers?.["X-Forwarded-For"]) return;
  const clientIp = headers["X-Forwarded-For"].split(",")[0].trim();
  if (clientIp) fp.ip_address = clientIp;
}

function extractPrivacySignals(
  device: ArgusPayload["device"],
  fp: Fingerprint,
) {
  const incognito = device.incognito as Record<string, unknown> | undefined;
  if (
    incognito &&
    (incognito.privateBrowsing === true || incognito.isPrivate === true)
  ) {
    fp.is_private_browsing = true;
  }

  const resistance = device.resistance as Record<string, unknown> | undefined;
  if (resistance) {
    const privacyVal = resistance.privacy;
    if (typeof privacyVal === "string" && privacyVal !== "unknown") {
      fp.privacy_browser = privacyVal;
    }
  }
}

function detectHeadless(
  headless: Record<string, unknown>,
): boolean | undefined {
  if (typeof headless.isHeadless === "boolean") return headless.isHeadless;
  const signals = headless.headless as Record<string, boolean> | undefined;
  return signals ? Object.values(signals).some(Boolean) : undefined;
}

function extractBotSignals(device: ArgusPayload["device"], fp: Fingerprint) {
  const headless = device.headless as Record<string, unknown> | undefined;
  if (headless) {
    const result = detectHeadless(headless);
    if (result !== undefined) fp.is_headless = result;
  }

  const lies = device.lies as Record<string, unknown> | undefined;
  if (lies) {
    const count =
      typeof lies.count === "number"
        ? lies.count
        : (lies.totalLies as number | undefined);
    if (typeof count === "number") fp.lie_count = count;
  }
}
