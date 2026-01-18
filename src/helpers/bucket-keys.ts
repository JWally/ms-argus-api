// src/helpers/bucket-keys.ts
// AR-117: Shared bucket key utilities for matching and profile services
// Single source of truth for Tier 2 bucket key generation

import { fnv1a } from "./hash";
import type { Fingerprint } from "../types/fingerprint";
import type { EvidenceCode } from "../types/matching";

/**
 * Bucket key info with evidence code for match tracking
 */
export interface BucketKeyInfo {
  key: string;
  evidenceCode: EvidenceCode;
}

/**
 * Build compound bucket keys with their evidence code types
 * Used for Tier 2 matching and evidence tracking
 */
export function buildBucketKeysWithTypes(
  fingerprint: Fingerprint,
): BucketKeyInfo[] {
  const buckets: BucketKeyInfo[] = [];

  // IP + JA4 (network identity)
  if (fingerprint.ip_address && fingerprint.ja4) {
    buckets.push({
      key: `ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`,
      evidenceCode: "IP_JA4_BUCKET",
    });
  }

  // GPU + Screen + Timezone (hardware/locale identity)
  if (
    fingerprint.gpu_renderer &&
    fingerprint.screen_dims &&
    fingerprint.timezone
  ) {
    buckets.push({
      key: `gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`,
      evidenceCode: "GPU_SCREEN_TZ_BUCKET",
    });
  }

  // Audio + Canvas (rendering identity)
  if (fingerprint.audio_hash && fingerprint.canvas_hash) {
    buckets.push({
      key: `audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`,
      evidenceCode: "AUDIO_CANVAS_BUCKET",
    });
  }

  // AR-80: Structural tier2 buckets (stable browser engine anchors)
  // These signals are based on browser internals that cannot be randomized
  // without breaking website functionality. Useful when canvas/audio are
  // blocked (e.g., Brave private browsing).

  // Maths + WindowFeatures (FPU + browser engine signals)
  if (fingerprint.maths_hash && fingerprint.window_features_hash) {
    buckets.push({
      key: `maths_window#${fingerprint.maths_hash}#${fingerprint.window_features_hash}`,
      evidenceCode: "MATHS_WINDOW_BUCKET",
    });
  }

  // HtmlElement + CSS (DOM/CSS capabilities)
  if (fingerprint.html_element_hash && fingerprint.css_hash) {
    buckets.push({
      key: `html_css#${fingerprint.html_element_hash}#${fingerprint.css_hash}`,
      evidenceCode: "HTML_CSS_BUCKET",
    });
  }

  // WebGL + Extensions + SVG (rendering capabilities)
  if (
    fingerprint.webgl_hash &&
    fingerprint.webgl_extensions_count !== undefined &&
    fingerprint.svg_hash
  ) {
    buckets.push({
      key: `webgl_struct#${fingerprint.webgl_hash}#${fingerprint.webgl_extensions_count}#${fingerprint.svg_hash}`,
      evidenceCode: "WEBGL_STRUCT_BUCKET",
    });
  }

  return buckets;
}

/**
 * Build compound bucket keys for Tier 2 matching
 * Returns just the key strings without evidence codes
 */
export function buildBucketKeys(fingerprint: Fingerprint): string[] {
  return buildBucketKeysWithTypes(fingerprint).map((info) => info.key);
}

/**
 * Alias for buildBucketKeys - used by profile-service
 * Maintains naming compatibility during refactor
 */
export const buildTier2BucketKeys = buildBucketKeys;

/**
 * AR-82: Build session anchor bucket key for ephemeral matching
 * Combines IP + User-Agent hash + Screen dimensions
 * Returns null if required signals are missing
 */
export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  if (
    !fingerprint.ip_address ||
    !fingerprint.user_agent ||
    !fingerprint.screen_dims
  ) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `session_anchor#${fingerprint.ip_address}#${uaHash}#${fingerprint.screen_dims}`;
}

/**
 * AR-94: Build IP+UA-only anchor bucket key for ephemeral matching
 * Does NOT include screen_dims - catches dock/undock screen changes
 * Returns null if required signals are missing
 */
export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  if (!fingerprint.ip_address || !fingerprint.user_agent) {
    return null;
  }

  const uaHash = fnv1a(fingerprint.user_agent);
  return `ip_ua_anchor#${fingerprint.ip_address}#${uaHash}`;
}
