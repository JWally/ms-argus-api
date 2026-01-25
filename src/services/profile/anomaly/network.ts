/**
 * Network anomaly detection.
 *
 * Detects anomalies in network-level signals such as timezone mismatches
 * between server-side geo-IP and client-reported values. These indicate
 * potential VPN/proxy usage or location spoofing.
 * @module
 */
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/** Minimum timezone offset difference (in hours) to flag as anomaly. */
const TZ_MISMATCH_THRESHOLD_HOURS = 3;

/** SigintData structure for network signals. */
interface SigintData {
  /** Geographic data from IP lookup */
  geo?: {
    /** IANA timezone from IP geolocation */
    timezone?: string;
  };
}

/**
 * Get UTC offset in minutes for a timezone
 * @param timezone - IANA timezone string (e.g., "America/New_York")
 * @returns Offset in minutes, or undefined if timezone is invalid
 */
function getUtcOffsetMinutes(timezone: string): number | undefined {
  try {
    const date = new Date();
    const utcDate = new Date(date.toLocaleString("en-US", { timeZone: "UTC" }));
    const tzDate = new Date(
      date.toLocaleString("en-US", { timeZone: timezone }),
    );
    return (tzDate.getTime() - utcDate.getTime()) / (1000 * 60);
  } catch {
    return undefined;
  }
}

/**
 * Detect network anomalies (timezone mismatches)
 *
 * @param fingerprint - Normalized fingerprint with timezone
 * @param raw - Raw payload (unused for network detection)
 * @param sigint - Signal intelligence data with geo
 * @returns Array of anomaly signals
 */
/**
 * Format timezone with UTC offset for display
 * @param tz - Timezone string
 * @param offset - UTC offset in minutes
 * @returns Formatted string like "America/New_York (UTC-5)"
 */
function formatTzOffset(tz: string, offset: number): string {
  const sign = offset >= 0 ? "+" : "";
  return `${tz} (UTC${sign}${(offset / 60).toFixed(0)})`;
}

/**
 * Detect timezone mismatch between server geo-IP and client reported timezone
 * @param serverTz - Server-side timezone from geo-IP lookup
 * @param clientTz - Client-reported timezone from JavaScript
 * @returns Anomaly signal if significant mismatch detected, null otherwise
 */
function detectTimezoneMismatch(
  serverTz: string,
  clientTz: string,
): AnomalySignal | null {
  if (serverTz === clientTz) return null;

  const serverOffset = getUtcOffsetMinutes(serverTz);
  const clientOffset = getUtcOffsetMinutes(clientTz);
  if (serverOffset === undefined || clientOffset === undefined) return null;

  const hoursDiff = Math.abs(serverOffset - clientOffset) / 60;
  if (hoursDiff < TZ_MISMATCH_THRESHOLD_HOURS) return null;

  // Severity scales with timezone difference: 0.4 base + 0.05 per hour, capped at 0.8
  const severity = Math.min(0.8, 0.4 + hoursDiff * 0.05);
  return createSignal("NETWORK", AnomalyCodes.IP_TIMEZONE_MISMATCH, severity, {
    expected: `Server timezone: ${formatTzOffset(serverTz, serverOffset)}`,
    actual: `Client timezone: ${formatTzOffset(clientTz, clientOffset)}`,
    fields: ["sigint.geo.timezone", "fingerprint.timezone"],
  });
}

/**
 * Detect network-related anomalies (timezone mismatches)
 * @param fingerprint - Normalized fingerprint with client timezone
 * @param _raw - Raw payload (unused for network detection)
 * @param sigint - Signal intelligence data with geo-IP timezone
 * @returns Array of detected network anomaly signals
 */
export function detectNetworkAnomalies(
  fingerprint: Fingerprint,
  _raw?: unknown,
  sigint?: SigintData,
): AnomalySignal[] {
  if (!sigint?.geo?.timezone || !fingerprint.timezone) {
    return [];
  }

  const signal = detectTimezoneMismatch(
    sigint.geo.timezone,
    fingerprint.timezone,
  );
  return signal ? [signal] : [];
}
