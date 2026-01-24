// src/services/profile/anomaly/network.ts
// AR-144: Network anomaly detection (timezone mismatch)

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Minimum timezone offset difference (in hours) to flag
 */
const TZ_MISMATCH_THRESHOLD_HOURS = 3;

/**
 * SigintData structure for network signals
 */
interface SigintData {
  geo?: {
    timezone?: string;
  };
}

/**
 * Get UTC offset in minutes for a timezone
 * Returns undefined if timezone is invalid
 */
function getUtcOffsetMinutes(timezone: string): number | undefined {
  try {
    // Create a date and format it in the given timezone
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
function formatTzOffset(tz: string, offset: number): string {
  const sign = offset >= 0 ? "+" : "";
  return `${tz} (UTC${sign}${(offset / 60).toFixed(0)})`;
}

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

  const severity = Math.min(0.8, 0.4 + hoursDiff * 0.05);
  return createSignal("NETWORK", AnomalyCodes.IP_TIMEZONE_MISMATCH, severity, {
    expected: `Server timezone: ${formatTzOffset(serverTz, serverOffset)}`,
    actual: `Client timezone: ${formatTzOffset(clientTz, clientOffset)}`,
    fields: ["sigint.geo.timezone", "fingerprint.timezone"],
  });
}

export function detectNetworkAnomalies(
  fingerprint: Fingerprint,
  _raw?: unknown,
  sigint?: SigintData,
): AnomalySignal[] {
  if (!sigint?.geo?.timezone || !fingerprint.timezone) {
    return [];
  }

  const signal = detectTimezoneMismatch(sigint.geo.timezone, fingerprint.timezone);
  return signal ? [signal] : [];
}
