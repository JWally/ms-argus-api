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
export function detectNetworkAnomalies(
  fingerprint: Fingerprint,
  _raw?: unknown,
  sigint?: SigintData,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  // Return empty if no sigint data
  if (!sigint) {
    return signals;
  }

  // Timezone Mismatch Detection - requires geo.timezone and fingerprint.timezone
  if (sigint.geo?.timezone && fingerprint.timezone) {
    const serverTz = sigint.geo.timezone;
    const clientTz = fingerprint.timezone;

    // Skip if exact match
    if (serverTz !== clientTz) {
      const serverOffset = getUtcOffsetMinutes(serverTz);
      const clientOffset = getUtcOffsetMinutes(clientTz);

      // Only flag if we can calculate both offsets
      if (serverOffset !== undefined && clientOffset !== undefined) {
        const hoursDiff = Math.abs(serverOffset - clientOffset) / 60;

        // Flag significant timezone mismatches (>3 hours)
        if (hoursDiff >= TZ_MISMATCH_THRESHOLD_HOURS) {
          // Severity scales with difference: 0.4 base + 0.05 per hour, max 0.8
          const severity = Math.min(0.8, 0.4 + hoursDiff * 0.05);

          signals.push(
            createSignal(
              "NETWORK",
              AnomalyCodes.IP_TIMEZONE_MISMATCH,
              severity,
              `Server timezone: ${serverTz} (UTC${serverOffset >= 0 ? "+" : ""}${(serverOffset / 60).toFixed(0)})`,
              `Client timezone: ${clientTz} (UTC${clientOffset >= 0 ? "+" : ""}${(clientOffset / 60).toFixed(0)})`,
              ["sigint.geo.timezone", "fingerprint.timezone"],
            ),
          );
        }
      }
    }
  }

  return signals;
}
