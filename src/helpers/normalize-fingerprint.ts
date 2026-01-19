// src/helpers/normalize-fingerprint.ts
// AR-73: Normalize fingerprint from web library nested format to flat API format
// AR-83: Added robust type coercion, validation, and sanitization
//
// The ms-argus-web library sends a complex nested FingerprintResult:
//   { loose: {...}, stable: {...}, hashes: {stable, fuzzy, ...}, botSignals: {...} }
//
// But the matching service expects flat Fingerprint fields:
//   { stable_hash, fuzzy_hash, canvas_hash, gpu_renderer, screen_dims, ... }
//
// This helper extracts and flattens the nested structure.

import type { Fingerprint } from "../types/fingerprint";
import type { SigintData } from "../types/matching";

// AR-83: Maximum string length to prevent storage issues
const MAX_STRING_LENGTH = 8192;

/**
 * AR-83: Safely coerce a value to a valid positive number.
 * Returns undefined if the value cannot be coerced or is invalid.
 */
function toValidNumber(val: unknown): number | undefined {
  if (val === undefined || val === null) return undefined;
  const num = typeof val === "string" ? parseFloat(val) : Number(val);
  if (!Number.isFinite(num)) return undefined;
  return num;
}

/**
 * AR-83: Safely coerce a value to a valid positive integer.
 * Returns undefined if the value is negative, NaN, or Infinity.
 */
function toValidPositiveNumber(val: unknown): number | undefined {
  const num = toValidNumber(val);
  if (num === undefined || num < 0) return undefined;
  return num;
}

/**
 * AR-83: Safely coerce a value to a boolean.
 * Handles string "true"/"false" as well as actual booleans.
 */
function toBoolean(val: unknown): boolean | undefined {
  if (typeof val === "boolean") return val;
  if (val === "true") return true;
  if (val === "false") return false;
  return undefined;
}

/**
 * AR-83: Safely coerce a value to a valid integer.
 * Returns undefined if invalid.
 */
function toValidInteger(val: unknown): number | undefined {
  const num = toValidNumber(val);
  if (num === undefined) return undefined;
  return Math.round(num);
}

/**
 * AR-83: Validate and sanitize a string value.
 * Returns undefined for empty/whitespace strings, sanitizes null bytes, truncates long strings.
 */
function sanitizeString(val: unknown): string | undefined {
  if (typeof val !== "string") return undefined;
  // Trim whitespace
  let str = val.trim();
  if (str.length === 0) return undefined;
  // Remove null bytes (using String.fromCharCode to avoid eslint no-control-regex)
  // eslint-disable-next-line no-control-regex
  str = str.replace(/\x00/g, "");
  if (str.length === 0) return undefined;
  // Truncate very long strings
  if (str.length > MAX_STRING_LENGTH) {
    str = str.substring(0, MAX_STRING_LENGTH);
  }
  return str;
}

/**
 * AR-83: Validate a score is in the 0-1 range.
 */
function toValidScore(val: unknown): number | undefined {
  const num = toValidNumber(val);
  if (num === undefined || num < 0 || num > 1) return undefined;
  return num;
}

/**
 * Web library FingerprintResult structure (nested)
 * AR-77: Fixed field names to match actual ms-argus-web library output
 */
interface WebFingerprintResult {
  // AR-64: Cryptographic device identity
  cryptoId?: {
    publicKey?: string;
    date?: string;
  };
  loose?: {
    // AR-77: canvas2d (not canvas)
    canvas2d?: { $hash?: string; [key: string]: unknown };
    // AR-77: offlineAudioContext (not audio)
    offlineAudioContext?: { $hash?: string; [key: string]: unknown };
    // AR-77: canvasWebgl (not webgl)
    canvasWebgl?: {
      gpu?: {
        compressedGPU?: string;
        renderer?: string;
        vendor?: string;
        [key: string]: unknown;
      };
      parameters?: { renderer?: string; [key: string]: unknown };
      extensions?: unknown[];
      $hash?: string;
      [key: string]: unknown;
    };
    screen?: {
      width?: number;
      height?: number;
      availWidth?: number;
      availHeight?: number;
      [key: string]: unknown;
    };
    timezone?: { location?: string; zone?: string; [key: string]: unknown };
    navigator?: {
      hardwareConcurrency?: number;
      deviceMemory?: number;
      platform?: string;
      [key: string]: unknown;
    };
    // AR-80: Structural fingerprint signals (stable browser engine anchors)
    maths?: { $hash?: string; [key: string]: unknown };
    windowFeatures?: { $hash?: string; [key: string]: unknown };
    htmlElementVersion?: { $hash?: string; [key: string]: unknown };
    css?: { $hash?: string; [key: string]: unknown };
    features?: { $hash?: string; [key: string]: unknown };
    svg?: { $hash?: string; [key: string]: unknown };
    clientRects?: { $hash?: string; [key: string]: unknown };
    intl?: { $hash?: string; [key: string]: unknown };
    consoleErrors?: { $hash?: string; [key: string]: unknown };
    [key: string]: unknown;
  };
  stable?: Record<string, unknown>;
  hashes?: {
    stable?: string;
    fuzzy?: string;
    loose?: string;
    deviceOfTimezone?: string;
  };
  botSignals?: {
    isHeadless?: boolean;
    hasLies?: boolean;
    lieCount?: number;
    botHash?: string;
    isPrivate?: boolean;
    likelyResidentialProxy?: boolean;
    stealthSignals?: Record<string, boolean>;
    [key: string]: unknown;
  };
  meta?: {
    timestamp?: number;
    durationMs?: number;
    version?: string;
  };
  // Direct fields (if already flat)
  stable_hash?: string;
  fuzzy_hash?: string;
  [key: string]: unknown;
}

/**
 * Normalize fingerprint from web library nested format to flat API format.
 * Handles both nested (web library) and already-flat (test/direct) formats.
 * AR-81: Also extracts fields from sigint data (third-party signals from ms-argus-web)
 *
 * @param raw - Raw fingerprint data (may be nested or flat)
 * @param sigint - Optional sigint data from ms-argus-web (TLS fingerprint, TCP probe, etc.)
 * @returns Normalized flat Fingerprint object
 */
export function normalizeFingerprint(
  raw: WebFingerprintResult | Fingerprint | undefined,
  sigint?: SigintData | null,
): Fingerprint {
  if (!raw) {
    return {};
  }

  // AR-83: If already flat (has stable_hash directly), still process sigint overrides
  if (
    typeof raw.stable_hash === "string" ||
    typeof raw.fuzzy_hash === "string"
  ) {
    // AR-XXX: Strip nested objects that might contain large numbers (e.g., loose.maths)
    // Only keep primitive fields (string, number, boolean, null, undefined)
    // This prevents DynamoDB marshalling errors from numbers > MAX_SAFE_INTEGER
    const result: Fingerprint = {};
    for (const [key, value] of Object.entries(raw)) {
      if (
        value === null ||
        value === undefined ||
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        (result as Record<string, unknown>)[key] = value;
      }
      // Skip objects and arrays (nested structures with potentially huge numbers)
    }

    // Apply sigint overrides even for flat fingerprints
    if (sigint) {
      if (sigint.tlsFingerprint && typeof sigint.tlsFingerprint === "object") {
        const tls = sigint.tlsFingerprint;
        const sigintId = sanitizeString(tls.id);
        if (sigintId) result.sigint_id = sigintId;
        const ja3 = sanitizeString(tls.ja3);
        if (ja3) result.ja3 = ja3;
        const ja4 = sanitizeString(tls.ja4);
        if (ja4) result.ja4 = ja4;
        const ip = sanitizeString(tls.ip);
        if (ip) result.ip_address = ip;
      }
      if (sigint.tcpProbe && typeof sigint.tcpProbe === "object") {
        const tcp = sigint.tcpProbe;
        const rttMs = toValidPositiveNumber(tcp.rttMs);
        if (rttMs !== undefined) result.tcp_rtt_us = Math.round(rttMs * 1000);
        const proxyScore = toValidScore(tcp.proxyScore);
        if (proxyScore !== undefined) result.proxy_score = proxyScore;
        const vpnScore = toValidScore(tcp.vpnScore);
        if (vpnScore !== undefined) result.vpn_score = vpnScore;
      }
      const faviconDeviceId = sanitizeString(sigint.faviconCache?.deviceId);
      if (faviconDeviceId) result.evercookie_id = faviconDeviceId;
    }

    return result;
  }

  const webFp = raw as WebFingerprintResult;
  const normalized: Fingerprint = {};

  // AR-83: Extract hashes with validation
  if (
    webFp.hashes &&
    typeof webFp.hashes === "object" &&
    !Array.isArray(webFp.hashes)
  ) {
    const stableHash = sanitizeString(webFp.hashes.stable);
    if (stableHash) {
      normalized.stable_hash = stableHash;
    }
    const fuzzyHash = sanitizeString(webFp.hashes.fuzzy);
    if (fuzzyHash) {
      normalized.fuzzy_hash = fuzzyHash;
    }
  }

  // AR-83: Extract from loose data with validation
  // Check that loose is actually an object (not array or primitive)
  if (
    webFp.loose &&
    typeof webFp.loose === "object" &&
    !Array.isArray(webFp.loose)
  ) {
    // AR-77: Canvas hash - field is canvas2d (not canvas)
    // AR-83: Validate $hash is actually a string
    const canvasHash = sanitizeString(webFp.loose.canvas2d?.$hash);
    if (canvasHash) {
      normalized.canvas_hash = canvasHash;
    }

    // AR-77: Audio hash - field is offlineAudioContext (not audio)
    const audioHash = sanitizeString(webFp.loose.offlineAudioContext?.$hash);
    if (audioHash) {
      normalized.audio_hash = audioHash;
    }

    // AR-77: WebGL / GPU renderer - field is canvasWebgl (not webgl)
    // AR-83: Validate GPU renderer is a string and not an object
    if (
      webFp.loose.canvasWebgl &&
      typeof webFp.loose.canvasWebgl === "object"
    ) {
      const webgl = webFp.loose.canvasWebgl;
      // Try multiple locations for GPU renderer - but only accept strings
      const gpuCandidate =
        webgl.gpu?.compressedGPU ||
        webgl.gpu?.renderer ||
        webgl.parameters?.renderer ||
        webgl.parameters?.UNMASKED_RENDERER_WEBGL;
      const gpuRenderer = sanitizeString(gpuCandidate);
      if (gpuRenderer) {
        normalized.gpu_renderer = gpuRenderer;
      }
      const webglHash = sanitizeString(webgl.$hash);
      if (webglHash) {
        normalized.webgl_hash = webglHash;
      }
      // WebGL extensions count (capability signal)
      if (Array.isArray(webgl.extensions)) {
        normalized.webgl_extensions_count = webgl.extensions.length;
      }
    }

    // AR-83: Screen dimensions with validation (must be positive numbers)
    if (webFp.loose.screen && typeof webFp.loose.screen === "object") {
      const screen = webFp.loose.screen;
      const width = toValidPositiveNumber(screen.width);
      const height = toValidPositiveNumber(screen.height);
      // Both must be positive (not zero, not negative)
      if (width && width > 0 && height && height > 0) {
        normalized.screen_dims = `${Math.round(width)}x${Math.round(height)}`;
      }
    }

    // Timezone with sanitization
    if (webFp.loose.timezone && typeof webFp.loose.timezone === "object") {
      const tz = webFp.loose.timezone;
      const timezone = sanitizeString(tz.location) || sanitizeString(tz.zone);
      if (timezone) {
        normalized.timezone = timezone;
      }
    }

    // AR-83: Navigator signals with type coercion
    if (webFp.loose.navigator && typeof webFp.loose.navigator === "object") {
      const nav = webFp.loose.navigator;
      const hardwareConcurrency = toValidPositiveNumber(
        nav.hardwareConcurrency,
      );
      if (hardwareConcurrency !== undefined) {
        normalized.hardware_concurrency = Math.round(hardwareConcurrency);
      }
      const deviceMemory = toValidPositiveNumber(nav.deviceMemory);
      if (deviceMemory !== undefined) {
        normalized.device_memory = deviceMemory;
      }
    }

    // AR-80: Structural fingerprint signals (stable browser engine anchors)
    // AR-83: All hashes validated through sanitizeString
    const mathsHash = sanitizeString(webFp.loose.maths?.$hash);
    if (mathsHash) {
      normalized.maths_hash = mathsHash;
    }
    const windowFeaturesHash = sanitizeString(
      webFp.loose.windowFeatures?.$hash,
    );
    if (windowFeaturesHash) {
      normalized.window_features_hash = windowFeaturesHash;
    }
    const htmlElementHash = sanitizeString(
      webFp.loose.htmlElementVersion?.$hash,
    );
    if (htmlElementHash) {
      normalized.html_element_hash = htmlElementHash;
    }
    const cssHash = sanitizeString(webFp.loose.css?.$hash);
    if (cssHash) {
      normalized.css_hash = cssHash;
    }
    const featuresHash = sanitizeString(webFp.loose.features?.$hash);
    if (featuresHash) {
      normalized.features_hash = featuresHash;
    }
    const svgHash = sanitizeString(webFp.loose.svg?.$hash);
    if (svgHash) {
      normalized.svg_hash = svgHash;
    }
    const clientRectsHash = sanitizeString(webFp.loose.clientRects?.$hash);
    if (clientRectsHash) {
      normalized.client_rects_hash = clientRectsHash;
    }
    const intlHash = sanitizeString(webFp.loose.intl?.$hash);
    if (intlHash) {
      normalized.intl_hash = intlHash;
    }
    const consoleErrorsHash = sanitizeString(webFp.loose.consoleErrors?.$hash);
    if (consoleErrorsHash) {
      normalized.console_errors_hash = consoleErrorsHash;
    }
  }

  // AR-83: Extract bot signals with type coercion
  if (
    webFp.botSignals &&
    typeof webFp.botSignals === "object" &&
    !Array.isArray(webFp.botSignals)
  ) {
    const bot = webFp.botSignals;
    const isHeadless = toBoolean(bot.isHeadless);
    if (isHeadless !== undefined) {
      normalized.is_headless = isHeadless;
    }
    const lieCount = toValidInteger(bot.lieCount);
    if (lieCount !== undefined && lieCount >= 0) {
      normalized.lie_count = lieCount;
    }
    const botHash = sanitizeString(bot.botHash);
    if (botHash) {
      normalized.bot_hash = botHash;
    }
    const isPrivate = toBoolean(bot.isPrivate);
    if (isPrivate !== undefined) {
      normalized.is_private_browsing = isPrivate;
    }
  }

  // AR-64: Extract cryptographic identity from nested cryptoId object
  if (
    webFp.cryptoId &&
    typeof webFp.cryptoId === "object" &&
    !Array.isArray(webFp.cryptoId)
  ) {
    const publicKey = sanitizeString(webFp.cryptoId.publicKey);
    if (publicKey) {
      normalized.public_key = publicKey;
    }
  }

  // Pass through any fields that are already in the expected format
  // (for backwards compatibility with clients that send flat data)
  const passthroughFields: (keyof Fingerprint)[] = [
    "evercookie_id",
    "sigint_id", // AR-81: Third-party cookie from sigint service
    "public_key",
    "ip_address",
    "ja3",
    "ja4",
    "user_agent",
    "tcp_rtt_us",
    "proxy_score",
    "vpn_score",
    "privacy_browser",
  ];

  for (const field of passthroughFields) {
    if (field in raw && raw[field as keyof typeof raw] !== undefined) {
      (normalized as Record<string, unknown>)[field] =
        raw[field as keyof typeof raw];
    }
  }

  // AR-81: Extract sigint data (third-party signals from ms-argus-web)
  // AR-83: Added type coercion and validation
  // These take precedence over any values already in fingerprint
  if (sigint) {
    // TLS fingerprint data (from CloudFront edge at id.argus.pw)
    if (sigint.tlsFingerprint && typeof sigint.tlsFingerprint === "object") {
      const tls = sigint.tlsFingerprint;

      // Third-party cookie ID - the key identifier for cross-site tracking
      const sigintId = sanitizeString(tls.id);
      if (sigintId) {
        normalized.sigint_id = sigintId;
      }

      // JA3/JA4 TLS fingerprints - override if present in sigint
      const ja3 = sanitizeString(tls.ja3);
      if (ja3) {
        normalized.ja3 = ja3;
      }
      const ja4 = sanitizeString(tls.ja4);
      if (ja4) {
        normalized.ja4 = ja4;
      }

      // IP address from edge (more reliable than X-Forwarded-For)
      const ip = sanitizeString(tls.ip);
      if (ip) {
        normalized.ip_address = ip;
      }
    }

    // TCP probe data with validation
    if (sigint.tcpProbe && typeof sigint.tcpProbe === "object") {
      const tcp = sigint.tcpProbe;

      // AR-83: Convert ms to μs for tcp_rtt_us, with type coercion and validation
      const rttMs = toValidPositiveNumber(tcp.rttMs);
      if (rttMs !== undefined) {
        normalized.tcp_rtt_us = Math.round(rttMs * 1000);
      }

      // AR-83: Validate scores are in 0-1 range
      const proxyScore = toValidScore(tcp.proxyScore);
      if (proxyScore !== undefined) {
        normalized.proxy_score = proxyScore;
      }

      const vpnScore = toValidScore(tcp.vpnScore);
      if (vpnScore !== undefined) {
        normalized.vpn_score = vpnScore;
      }
    }

    // Favicon cache device ID (evercookie-like persistence)
    const faviconDeviceId = sanitizeString(sigint.faviconCache?.deviceId);
    if (faviconDeviceId) {
      normalized.evercookie_id = faviconDeviceId;
    }
  }

  return normalized;
}
