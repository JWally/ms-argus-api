// src/helpers/normalize-fingerprint.ts
// AR-73: Normalize fingerprint from matching-worker flat format
// AR-83: Added robust type coercion, validation, and sanitization
// AR-XXX: Simplified to only handle flat fingerprints (nested web format removed)
//
// The matching-worker now extracts flat fingerprints from V3 payloads via extractFingerprint().
// This helper sanitizes those flat fingerprints and applies sigint overrides.

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
 * Normalize and sanitize a flat fingerprint, applying sigint overrides.
 *
 * The fingerprint is already flat when it arrives here (extracted by matching-worker).
 * This function:
 * 1. Strips nested objects that might contain large numbers (DynamoDB safety)
 * 2. Applies sigint overrides (TLS fingerprint, TCP probe data)
 *
 * @param raw - Flat fingerprint data from matching-worker
 * @param sigint - Optional sigint data from ms-argus-web (TLS fingerprint, TCP probe, etc.)
 * @returns Sanitized flat Fingerprint object
 */
export function normalizeFingerprint(
  raw: Fingerprint | undefined,
  sigint?: SigintData | null,
): Fingerprint {
  if (!raw) {
    return {};
  }

  // AR-146: Strip nested objects that might contain large numbers (e.g., maths)
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

  // Apply sigint overrides
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
