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

/**
 * Web library FingerprintResult structure (nested)
 */
interface WebFingerprintResult {
  loose?: {
    canvas?: { $hash?: string; [key: string]: unknown };
    audio?: { $hash?: string; [key: string]: unknown };
    webgl?: {
      gpu?: string;
      parameters?: { renderer?: string; [key: string]: unknown };
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
 *
 * @param raw - Raw fingerprint data (may be nested or flat)
 * @returns Normalized flat Fingerprint object
 */
export function normalizeFingerprint(
  raw: WebFingerprintResult | Fingerprint | undefined,
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
    // Canvas hash
    if (webFp.loose.canvas?.$hash) {
      normalized.canvas_hash = webFp.loose.canvas.$hash;
    }

    // Audio hash
    if (webFp.loose.audio?.$hash) {
      normalized.audio_hash = webFp.loose.audio.$hash;
    }

    // WebGL / GPU renderer
    if (webFp.loose.webgl) {
      const webgl = webFp.loose.webgl;
      // Try multiple locations for GPU renderer
      const gpuRenderer =
        webgl.gpu ||
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

  return normalized;
}
