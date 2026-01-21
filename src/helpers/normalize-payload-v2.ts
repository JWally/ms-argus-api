// src/helpers/normalize-payload-v2.ts
// AR-183: Normalize v1 payloads to v2 schema format
// This enables backward compatibility during the migration period

import type { FingerprintPayload } from "../types";

// V2 Schema types (matches @argus/schema definitions)
export interface IdentifiersV2 {
  session_id: string;
  device_id?: string;
  evercookie_id?: string;
  public_key?: string;
}

export interface DeviceHashesV2 {
  stable: string;
  fuzzy: string;
  canvas?: string;
  webgl?: string;
  audio?: string;
  fonts?: string;
}

export interface DeviceV2 {
  hashes: DeviceHashesV2;
  user_agent: string;
  platform: string;
  language: string;
  languages: string[];
  hardware_concurrency?: number;
  device_memory?: number;
  max_touch_points?: number;
  screen_width: number;
  screen_height: number;
  color_depth: number;
  pixel_ratio: number;
  gpu_vendor?: string;
  gpu_renderer?: string;
  canvas_data?: string;
  audio_data?: string;
  fonts_list?: string[];
  timezone_offset: number;
  timezone_name: string;
  webdriver: boolean;
  headless_signals: string[];
}

export interface NetworkV2 {
  ip: string;
  geo?: {
    country: string;
    city?: string;
    asn?: string;
  };
  is_proxy?: boolean;
  is_vpn?: boolean;
  ja3?: string;
  ja4?: string;
  headers: Record<string, string>;
  webrtc_local_ip?: string;
  webrtc_public_ip?: string;
}

export interface AnalysisV2 {
  status: "pending" | "complete" | "degraded" | "error";
  confidence: number;
  match_tier: number;
  risk_score: number;
  flags: string[];
  evidence_codes: string[];
  processing_ms?: number;
}

export interface ArgusPayloadV2 {
  identifiers: IdentifiersV2;
  device: DeviceV2;
  network?: NetworkV2;
  analysis?: AnalysisV2;
}

// ==================== CONFIGURATION ====================

/**
 * Get the V1 sunset date from environment
 * After this date, V1 payloads will be rejected
 */
export function getV1SunsetDate(): Date {
  const envDate = process.env.V1_SUNSET_DATE;
  if (envDate) {
    const parsed = new Date(envDate);
    if (!isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  // Default: 30 days from now (will be set properly on deploy)
  const defaultDate = new Date();
  defaultDate.setDate(defaultDate.getDate() + 30);
  return defaultDate;
}

/**
 * Check if V1 compatibility is still enabled
 * Based on the V1_SUNSET_DATE configuration
 */
export function isV1CompatibilityEnabled(): boolean {
  return Date.now() < getV1SunsetDate().getTime();
}

export const V1_COMPATIBILITY_ENABLED = isV1CompatibilityEnabled();

// ==================== DETECTION ====================

/**
 * Check if a payload is in V1 format
 * V1 has: session_id at root, fingerprint object
 */
export function isV1Payload(input: unknown): boolean {
  if (!input || typeof input !== "object") {
    return false;
  }

  const obj = input as Record<string, unknown>;

  // V1 has session_id at root level and a fingerprint object
  return (
    typeof obj.session_id === "string" &&
    obj.fingerprint !== undefined &&
    typeof obj.fingerprint === "object"
  );
}

/**
 * Check if a payload is in V2 format
 * V2 has: identifiers.session_id and device.hashes
 */
export function isV2Payload(input: unknown): boolean {
  if (!input || typeof input !== "object") {
    return false;
  }

  const obj = input as Record<string, unknown>;

  // V2 has identifiers.session_id and device.hashes structure
  if (
    !obj.identifiers ||
    typeof obj.identifiers !== "object" ||
    !("session_id" in (obj.identifiers as object))
  ) {
    return false;
  }

  if (
    !obj.device ||
    typeof obj.device !== "object" ||
    !("hashes" in (obj.device as object))
  ) {
    return false;
  }

  return true;
}

// ==================== NORMALIZATION ====================

/**
 * Parse screen dimensions from "WIDTHxHEIGHT" string
 */
function parseScreenDims(dims: string | undefined): {
  width: number;
  height: number;
} {
  if (!dims) {
    return { width: 1920, height: 1080 }; // Default
  }
  const match = dims.match(/^(\d+)x(\d+)$/);
  if (match) {
    return { width: parseInt(match[1], 10), height: parseInt(match[2], 10) };
  }
  return { width: 1920, height: 1080 };
}

/**
 * Normalize any payload to V2 format
 * If already V2, returns as-is
 * If V1, transforms to V2 structure
 */
export function normalizeToV2(input: unknown): ArgusPayloadV2 {
  // Already V2 - return as-is
  if (isV2Payload(input)) {
    return input as ArgusPayloadV2;
  }

  // Must be V1 - transform
  if (!isV1Payload(input)) {
    throw new Error("Invalid payload format: not V1 or V2");
  }

  const v1 = input as FingerprintPayload;
  const fp = v1.fingerprint;

  // Extract screen dimensions
  const screenDims = parseScreenDims(fp.screen_dims);

  // Build headless signals from bot detection
  const headlessSignals: string[] = [];
  if (fp.lie_count && fp.lie_count > 0) {
    headlessSignals.push("lies_detected");
  }
  if (fp.is_headless) {
    headlessSignals.push("headless_browser");
  }

  // Build identifiers
  const identifiers: IdentifiersV2 = {
    session_id: v1.session_id,
  };
  if (fp.evercookie_id) {
    identifiers.evercookie_id = fp.evercookie_id;
  }
  if (fp.public_key) {
    identifiers.public_key = fp.public_key;
  }

  // Build device hashes
  const hashes: DeviceHashesV2 = {
    stable: fp.stable_hash || "",
    fuzzy: fp.fuzzy_hash || "",
  };
  if (fp.canvas_hash) hashes.canvas = fp.canvas_hash;
  if (fp.webgl_hash) hashes.webgl = fp.webgl_hash;
  if (fp.audio_hash) hashes.audio = fp.audio_hash;

  // Build device
  const device: DeviceV2 = {
    hashes,
    user_agent: fp.user_agent || v1.headers?.["user-agent"] || "unknown",
    platform: "unknown", // Not in v1 flat fingerprint
    language: "en-US", // Not in v1 flat fingerprint
    languages: ["en-US"],
    screen_width: screenDims.width,
    screen_height: screenDims.height,
    color_depth: 24, // Default
    pixel_ratio: 1, // Default
    timezone_offset: 0, // Not in v1 flat fingerprint
    timezone_name: fp.timezone || "UTC",
    webdriver: fp.is_headless || false,
    headless_signals: headlessSignals,
  };

  // Optional device fields
  if (fp.gpu_renderer) device.gpu_renderer = fp.gpu_renderer;
  if (fp.hardware_concurrency)
    device.hardware_concurrency = fp.hardware_concurrency;
  if (fp.device_memory) device.device_memory = fp.device_memory;

  // Build network from sigint and headers
  const sigint = v1.sigint;
  const ip = sigint?.tlsFingerprint?.ip || fp.ip_address || "0.0.0.0";

  const network: NetworkV2 = {
    ip,
    headers: v1.headers || {},
  };

  if (sigint?.tlsFingerprint?.ja3) {
    network.ja3 = sigint.tlsFingerprint.ja3;
  } else if (fp.ja3) {
    network.ja3 = fp.ja3;
  }

  if (sigint?.tlsFingerprint?.ja4) {
    network.ja4 = sigint.tlsFingerprint.ja4;
  } else if (fp.ja4) {
    network.ja4 = fp.ja4;
  }

  if (sigint?.tcpProbe?.proxyScore !== undefined) {
    network.is_proxy = sigint.tcpProbe.proxyScore > 0.5;
  }
  if (sigint?.tcpProbe?.vpnScore !== undefined) {
    network.is_vpn = sigint.tcpProbe.vpnScore > 0.5;
  }

  if (sigint?.stun?.localIps?.[0]) {
    network.webrtc_local_ip = sigint.stun.localIps[0];
  }
  if (sigint?.stun?.publicIp) {
    network.webrtc_public_ip = sigint.stun.publicIp;
  }

  return {
    identifiers,
    device,
    network,
  };
}
