/**
 * Fingerprint normalization and sanitization.
 *
 * Cleans incoming fingerprint data by stripping nested objects (to prevent
 * DynamoDB marshalling errors with large numbers) and applying signal
 * intelligence overrides from ms-argus-web.
 * @module
 */
import type { Fingerprint } from "../types/fingerprint";
import type { SigintData } from "../types/matching";

/** Maximum allowed string length to prevent DoS via large payloads. */
const MAX_STRING_LENGTH = 8192;

/**
 * Safely coerce a value to a valid positive number.
 * @param val - Value to coerce
 * @returns Number if valid, undefined otherwise
 */
function toValidNumber(val: unknown): number | undefined {
  if (val === undefined || val === null) return undefined;
  const num = typeof val === "string" ? parseFloat(val) : Number(val);
  if (!Number.isFinite(num)) return undefined;
  return num;
}

/**
 * Safely coerce a value to a valid positive number.
 * @param val - Value to coerce
 * @returns Positive number if valid, undefined if negative/invalid
 */
function toValidPositiveNumber(val: unknown): number | undefined {
  const num = toValidNumber(val);
  if (num === undefined || num < 0) return undefined;
  return num;
}

/**
 * Validate and sanitize a string value.
 * @param val - Value to sanitize
 * @returns Sanitized string, or undefined if empty/invalid
 */
function sanitizeString(val: unknown): string | undefined {
  if (typeof val !== "string") return undefined;
  let str = val.trim();
  if (str.length === 0) return undefined;
  // eslint-disable-next-line no-control-regex
  str = str.replace(/\x00/g, "");
  if (str.length === 0) return undefined;
  if (str.length > MAX_STRING_LENGTH) {
    str = str.substring(0, MAX_STRING_LENGTH);
  }
  return str;
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

  // Only keep primitive fields to prevent DynamoDB marshalling errors from numbers > MAX_SAFE_INTEGER
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
  }

  if (sigint) applySigintOverrides(sigint, result);

  return result;
}

/**
 * Apply TLS fingerprint overrides to fingerprint
 * @param tls - TLS fingerprint data from sigint
 * @param fp - Fingerprint to modify
 */
function applyTlsOverrides(
  tls: NonNullable<SigintData["aws_cf"]>,
  fp: Fingerprint,
) {
  const sigintId = sanitizeString(tls.id);
  if (sigintId) fp.sigint_id = sigintId;
  const ja3 = sanitizeString(tls.ja3);
  if (ja3) fp.ja3 = ja3;
  const ja4 = sanitizeString(tls.ja4);
  if (ja4) fp.ja4 = ja4;
  const ip = sanitizeString(tls.ip);
  if (ip) fp.ip_address = ip;
}

/**
 * Apply TCP probe overrides to fingerprint
 * @param tcp - TCP probe data from sigint
 * @param fp - Fingerprint to modify
 */
function applyTcpOverrides(
  tcp: NonNullable<SigintData["tcp_probe"]>,
  fp: Fingerprint,
) {
  const rttMs = toValidPositiveNumber(tcp.rttMs);
  if (rttMs !== undefined) fp.tcp_rtt_us = Math.round(rttMs * 1000);
}

/**
 * Apply all sigint overrides (TLS, TCP, favicon) to fingerprint
 * @param sigint - Signal intelligence data
 * @param fp - Fingerprint to modify
 */
function applySigintOverrides(sigint: SigintData, fp: Fingerprint) {
  if (sigint.aws_cf && typeof sigint.aws_cf === "object") {
    applyTlsOverrides(sigint.aws_cf, fp);
  }
  if (sigint.tcp_probe && typeof sigint.tcp_probe === "object") {
    applyTcpOverrides(sigint.tcp_probe, fp);
  }
  const faviconDeviceId = sanitizeString(sigint.faviconCache?.deviceId);
  if (faviconDeviceId) fp.evercookie_id = faviconDeviceId;
}
