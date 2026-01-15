// src/helpers/normalize-fingerprint.ts
// AR-73: Normalize fingerprint from web library nested format to flat API format
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

/**
 * Web library FingerprintResult structure (nested)
 * AR-77: Fixed field names to match actual ms-argus-web library output
 */
interface WebFingerprintResult {
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

  // If already flat (has stable_hash directly), return as-is with minimal processing
  if (
    typeof raw.stable_hash === "string" ||
    typeof raw.fuzzy_hash === "string"
  ) {
    return raw as Fingerprint;
  }

  const webFp = raw as WebFingerprintResult;
  const normalized: Fingerprint = {};

  // Extract hashes
  if (webFp.hashes) {
    if (webFp.hashes.stable) {
      normalized.stable_hash = webFp.hashes.stable;
    }
    if (webFp.hashes.fuzzy) {
      normalized.fuzzy_hash = webFp.hashes.fuzzy;
    }
  }

  // Extract from loose data
  if (webFp.loose) {
    // AR-77: Canvas hash - field is canvas2d (not canvas)
    if (webFp.loose.canvas2d?.$hash) {
      normalized.canvas_hash = webFp.loose.canvas2d.$hash;
    }

    // AR-77: Audio hash - field is offlineAudioContext (not audio)
    if (webFp.loose.offlineAudioContext?.$hash) {
      normalized.audio_hash = webFp.loose.offlineAudioContext.$hash;
    }

    // AR-77: WebGL / GPU renderer - field is canvasWebgl (not webgl)
    // GPU is at canvasWebgl.gpu.compressedGPU (not webgl.gpu)
    if (webFp.loose.canvasWebgl) {
      const webgl = webFp.loose.canvasWebgl;
      // Try multiple locations for GPU renderer
      const gpuRenderer =
        webgl.gpu?.compressedGPU ||
        webgl.gpu?.renderer ||
        webgl.parameters?.renderer ||
        (webgl.parameters?.UNMASKED_RENDERER_WEBGL as string | undefined);
      if (gpuRenderer) {
        normalized.gpu_renderer = gpuRenderer;
      }
      if (webgl.$hash) {
        normalized.webgl_hash = webgl.$hash;
      }
    }

    // Screen dimensions
    if (webFp.loose.screen) {
      const screen = webFp.loose.screen;
      if (screen.width && screen.height) {
        normalized.screen_dims = `${screen.width}x${screen.height}`;
      }
    }

    // Timezone
    if (webFp.loose.timezone) {
      const tz = webFp.loose.timezone;
      normalized.timezone = tz.location || tz.zone;
    }

    // Navigator signals
    if (webFp.loose.navigator) {
      const nav = webFp.loose.navigator;
      if (typeof nav.hardwareConcurrency === "number") {
        normalized.hardware_concurrency = nav.hardwareConcurrency;
      }
      if (typeof nav.deviceMemory === "number") {
        normalized.device_memory = nav.deviceMemory;
      }
    }

    // AR-80: Structural fingerprint signals (stable browser engine anchors)
    // These signals are based on browser internals that cannot be randomized
    // without breaking website functionality. Useful for tier2 matching
    // when canvas/audio are blocked (e.g., Brave).

    if (webFp.loose.maths?.$hash) {
      normalized.maths_hash = webFp.loose.maths.$hash;
    }
    if (webFp.loose.windowFeatures?.$hash) {
      normalized.window_features_hash = webFp.loose.windowFeatures.$hash;
    }
    if (webFp.loose.htmlElementVersion?.$hash) {
      normalized.html_element_hash = webFp.loose.htmlElementVersion.$hash;
    }
    if (webFp.loose.css?.$hash) {
      normalized.css_hash = webFp.loose.css.$hash;
    }
    if (webFp.loose.features?.$hash) {
      normalized.features_hash = webFp.loose.features.$hash;
    }
    if (webFp.loose.svg?.$hash) {
      normalized.svg_hash = webFp.loose.svg.$hash;
    }
    if (webFp.loose.clientRects?.$hash) {
      normalized.client_rects_hash = webFp.loose.clientRects.$hash;
    }
    if (webFp.loose.intl?.$hash) {
      normalized.intl_hash = webFp.loose.intl.$hash;
    }
    if (webFp.loose.consoleErrors?.$hash) {
      normalized.console_errors_hash = webFp.loose.consoleErrors.$hash;
    }
    // WebGL extensions count (capability signal)
    if (webFp.loose.canvasWebgl?.extensions) {
      normalized.webgl_extensions_count =
        webFp.loose.canvasWebgl.extensions.length;
    }
  }

  // Extract bot signals
  if (webFp.botSignals) {
    const bot = webFp.botSignals;
    if (typeof bot.isHeadless === "boolean") {
      normalized.is_headless = bot.isHeadless;
    }
    if (typeof bot.lieCount === "number") {
      normalized.lie_count = bot.lieCount;
    }
    if (bot.botHash) {
      normalized.bot_hash = bot.botHash;
    }
    if (typeof bot.isPrivate === "boolean") {
      normalized.is_private_browsing = bot.isPrivate;
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
  // These take precedence over any values already in fingerprint
  if (sigint) {
    // TLS fingerprint data (from CloudFront edge at id.argus.pw)
    if (sigint.tlsFingerprint) {
      const tls = sigint.tlsFingerprint;

      // Third-party cookie ID - the key identifier for cross-site tracking
      if (tls.id) {
        normalized.sigint_id = tls.id;
      }

      // JA3/JA4 TLS fingerprints - override if present in sigint
      if (tls.ja3) {
        normalized.ja3 = tls.ja3;
      }
      if (tls.ja4) {
        normalized.ja4 = tls.ja4;
      }

      // IP address from edge (more reliable than X-Forwarded-For)
      if (tls.ip) {
        normalized.ip_address = tls.ip;
      }
    }

    // TCP probe data
    if (sigint.tcpProbe) {
      const tcp = sigint.tcpProbe;

      // Convert ms to μs for tcp_rtt_us
      if (typeof tcp.rttMs === "number") {
        normalized.tcp_rtt_us = Math.round(tcp.rttMs * 1000);
      }

      if (typeof tcp.proxyScore === "number") {
        normalized.proxy_score = tcp.proxyScore;
      }

      if (typeof tcp.vpnScore === "number") {
        normalized.vpn_score = tcp.vpnScore;
      }
    }

    // Favicon cache device ID (evercookie-like persistence)
    if (sigint.faviconCache?.deviceId) {
      normalized.evercookie_id = sigint.faviconCache.deviceId;
    }
  }

  return normalized;
}
