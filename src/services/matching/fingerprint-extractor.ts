import type { ArgusPayload } from "../../helpers/payload-schema";
import type { Fingerprint } from "../../types";

/** Map client-sent resistance.privacy values to API-internal canonical forms. */
const PRIVACY_BROWSER_MAP: Record<string, string> = {
  Brave: "brave",
  Firefox: "firefox_rfp",
  "Tor Browser": "tor",
};

/**
 * Extract flat fingerprint fields from V3 payload.
 * Pure transformation: no AWS calls, no side effects.
 * Normalizes the nested V3 payload structure into a flat fingerprint object.
 * @param payload - The V3 Argus payload from the client
 * @param headers - Optional HTTP headers for IP fallback extraction
 * @returns Flat fingerprint object with all extracted signals
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

/**
 * Extract identity signals (evercookie, public key) from identifiers section
 * @param identifiers - The identifiers section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractIdentifiers(
  identifiers: ArgusPayload["identifiers"],
  fp: Fingerprint,
) {
  if (identifiers.evercookie_id) fp.evercookie_id = identifiers.evercookie_id;
  if (identifiers.public_key) fp.public_key = identifiers.public_key;
}

/**
 * Extract device info from worker scope (userAgent, hardware, GPU, timezone)
 * Worker scope provides more reliable values than navigator in some cases
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
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
  if (typeof workerScope.platform === "string")
    fp.platform = workerScope.platform;
}

/**
 * Extract GPU renderer from canvas WebGL if not already set from worker scope
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractGpuFallback(device: ArgusPayload["device"], fp: Fingerprint) {
  if (fp.gpu_renderer) return;
  const gpu = device.canvasWebgl?.gpu as Record<string, unknown> | undefined;
  if (gpu?.compressedGPU && typeof gpu.compressedGPU === "string") {
    fp.gpu_renderer = gpu.compressedGPU;
  }
}

/**
 * Extract screen dimensions as "widthxheight" string
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractScreen(device: ArgusPayload["device"], fp: Fingerprint) {
  const screen = device.screen;
  if (!screen) return;
  const { width, height } = screen;
  if (typeof width === "number" && typeof height === "number") {
    fp.screen_dims = `${width}x${height}`;
  }
}

/**
 * Mapping of source hash fields to fingerprint fields
 * Each tuple maps [sourceField, targetField]
 */
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
  ["screen", "screen_hash"],
  ["cssMedia", "css_media_hash"],
];

/**
 * Mapping of SimHash fields (underscore-prefixed) to fingerprint fields
 * SimHashes are 256-bit locality-sensitive hashes for similarity matching
 */
const SIMHASH_FIELD_MAP: [string, keyof Fingerprint][] = [
  ["_maths", "maths_simhash"],
  ["_windowFeatures", "window_features_simhash"],
  ["_htmlElementVersion", "html_element_simhash"],
  ["_css", "css_simhash"],
  ["_svg", "svg_simhash"],
  ["_intl", "intl_simhash"],
  ["_features", "features_simhash"],
  ["_clientRects", "client_rects_simhash"],
  ["_fonts", "fonts_simhash"],
  ["_canvas2d", "canvas_simhash"],
  ["_canvasWebgl", "webgl_simhash"],
  ["_offlineAudioContext", "audio_simhash"],
  ["_screen", "screen_simhash"],
  ["_cssMedia", "css_media_simhash"],
];

/**
 * Extract all hash fields (canvas, webgl, audio, etc.) from hashes section
 * Includes both SHA-256 hashes and SimHash variants for similarity matching
 * @param hashes - The hashes section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractHashes(hashes: ArgusPayload["hashes"], fp: Fingerprint) {
  // Extract SHA-256 hashes
  for (const [src, dst] of HASH_FIELD_MAP) {
    if (hashes[src]) (fp as Record<string, unknown>)[dst] = hashes[src];
  }

  // Extract SimHash variants (underscore-prefixed, 256-bit locality-sensitive)
  const hashesRecord = hashes as Record<string, unknown>;
  for (const [src, dst] of SIMHASH_FIELD_MAP) {
    if (hashesRecord[src])
      (fp as Record<string, unknown>)[dst] = hashesRecord[src];
  }
}

/**
 * Extract count of WebGL extensions supported by the device.
 * Handles both raw arrays and compacted format { $simhash, $len }.
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractWebglExtensions(
  device: ArgusPayload["device"],
  fp: Fingerprint,
) {
  const webglData = device.canvasWebgl;
  if (!webglData) return;

  const extensions = webglData.extensions;
  if (Array.isArray(extensions)) {
    fp.webgl_extensions_count = extensions.length;
  } else if (
    extensions &&
    typeof extensions === "object" &&
    "$len" in extensions
  ) {
    // Handle compacted format: { $simhash: "...", $len: N }
    fp.webgl_extensions_count = (extensions as { $len: number }).$len;
  }
}

/**
 * Extract TLS fingerprint fields (IP, JA3, JA4, sigint ID)
 * @param tls - The TLS fingerprint section from sigint
 * @param fp - The fingerprint object to populate
 */
function extractTlsFields(
  tls: NonNullable<ArgusPayload["sigint"]>["aws_cf"],
  fp: Fingerprint,
) {
  if (!tls) return;
  if (tls.ip) fp.ip_address = tls.ip;
  if (tls.ja3) fp.ja3 = tls.ja3;
  if (tls.ja4 && !fp.ja4) fp.ja4 = tls.ja4;
  if (tls.id) fp.sigint_id = tls.id;
}

/**
 * Extract H2 probe data (HTTP/2 fingerprint) from sigint
 * @param sigint - The sigint section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractH2Probe(
  sigint: NonNullable<ArgusPayload["sigint"]>,
  fp: Fingerprint,
) {
  const h2 = sigint.h2;
  if (!h2) return;

  if (Array.isArray(h2.settings_order))
    fp.h2_settings_order = h2.settings_order;
  if (typeof h2.window_update === "number")
    fp.h2_window_update = h2.window_update;
  if (typeof h2.pseudo_header_order === "string")
    fp.h2_pseudo_header_order = h2.pseudo_header_order;
  if (Array.isArray(h2.header_order)) fp.h2_header_order = h2.header_order;
  if (typeof h2.fingerprint === "string")
    fp.h2_fingerprint_raw = h2.fingerprint;
}

/**
 * Extract signal intelligence data (TLS, TCP, H2, favicon cache, STUN)
 * @param sigint - The sigint section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractSigint(sigint: ArgusPayload["sigint"], fp: Fingerprint) {
  if (!sigint) return;
  extractTcpProbe(sigint, fp);
  extractTlsFields(sigint.aws_cf, fp);
  extractH2Probe(sigint, fp);
  if (sigint.faviconCache?.id) fp.favicon_cache_id = sigint.faviconCache.id;
}

/**
 * Apply TCP fingerprint fields to the fingerprint
 * Handles both legacy (camelCase) and modern (snake_case) field names
 * @param source - Source object containing TCP fields
 * @param fp - The fingerprint object to populate
 * @param legacy - Whether to use legacy field names
 */
function applyTcpFields(
  source: Record<string, unknown>,
  fp: Fingerprint,
  legacy: boolean,
) {
  const rttKey = legacy ? "rttMs" : "tcp_rtt_us";

  if (typeof source[rttKey] === "number") {
    fp.tcp_rtt_us = legacy
      ? (source[rttKey] as number) * 1000
      : (source[rttKey] as number);
  }
}

/** Extract snd_mss and pmtu from rtt_fingerprint (modern format only). */
function applyMssFields(source: Record<string, unknown>, fp: Fingerprint) {
  if (typeof source.snd_mss === "number") fp.snd_mss = source.snd_mss;
  if (typeof source.pmtu === "number") fp.pmtu = source.pmtu;
}

/**
 * Extract TCP probe data (RTT, MSS, JA4)
 * @param sigint - The sigint section from the payload
 * @param fp - The fingerprint object to populate
 */
function extractTcpProbe(
  sigint: NonNullable<ArgusPayload["sigint"]>,
  fp: Fingerprint,
) {
  if (!sigint.tcp_probe) return;
  const tcp = sigint.tcp_probe as Record<string, unknown>;
  const rttFp = tcp.rtt_fingerprint as Record<string, unknown> | undefined;
  applyTcpFields(rttFp || tcp, fp, !rttFp);
  // JA4 from probe server (top-level on tcp_probe) — primary source; aws_cf.ja4 is fallback
  if (typeof tcp.ja4 === "string") fp.ja4 = tcp.ja4;
  if (rttFp) applyMssFields(rttFp, fp);
}

/**
 * Extract IP address from X-Forwarded-For header as fallback
 * Only used if IP wasn't extracted from TLS fingerprint
 * @param headers - HTTP headers from the request
 * @param fp - The fingerprint object to populate
 */
function extractIpFallback(
  headers: Record<string, string> | undefined,
  fp: Fingerprint,
) {
  if (fp.ip_address || !headers?.["X-Forwarded-For"]) return;
  const clientIp = headers["X-Forwarded-For"].split(",")[0].trim();
  if (clientIp) fp.ip_address = clientIp;
}

/**
 * Extract privacy browser and private browsing mode signals
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
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
      fp.privacy_browser = PRIVACY_BROWSER_MAP[privacyVal] ?? privacyVal;
    }
  }
}

/**
 * Detect if browser is running in headless mode
 * @param headless - The headless detection section
 * @returns True if headless detected, false if not, undefined if unknown
 */
function detectHeadless(
  headless: Record<string, unknown>,
): boolean | undefined {
  if (typeof headless.isHeadless === "boolean") return headless.isHeadless;
  const signals = headless.headless as Record<string, boolean> | undefined;
  return signals ? Object.values(signals).some(Boolean) : undefined;
}

/**
 * Extract bot detection signals (headless browser, lie count)
 * @param device - The device section from the payload
 * @param fp - The fingerprint object to populate
 */
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
