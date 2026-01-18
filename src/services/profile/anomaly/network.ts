// src/services/profile/anomaly/network.ts
// AR-144: Network anomaly detection (FTL, timezone mismatch)

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Server location: Reston, VA (AWS us-east-1)
 */
const SERVER_LOCATION = {
  lat: 38.9586,
  lon: -77.357,
};

/**
 * Fiber optic speed in km/ms (⅔ speed of light due to refractive index)
 * Speed of light: ~299,792 km/s = ~300 km/ms
 * Fiber: ~200,000 km/s = ~200 km/ms
 */
const FIBER_SPEED_KM_PER_MS = 200;

/**
 * FTL detection tolerance (10%)
 * Accounts for measurement jitter
 */
const FTL_TOLERANCE = 0.9;

/**
 * Minimum timezone offset difference (in hours) to flag
 */
const TZ_MISMATCH_THRESHOLD_HOURS = 3;

/**
 * SigintData structure for network signals
 */
interface SigintData {
  geo?: {
    lat?: number;
    lon?: number;
    timezone?: string;
  };
  tcpProbe?: {
    rttMs?: number;
  };
}

/**
 * Convert degrees to radians
 */
function toRad(deg: number): number {
  return deg * (Math.PI / 180);
}

/**
 * Calculate great circle distance between two points using Haversine formula
 *
 * @param lat1 - Latitude of point 1 in degrees
 * @param lon1 - Longitude of point 1 in degrees
 * @param lat2 - Latitude of point 2 in degrees
 * @param lon2 - Longitude of point 2 in degrees
 * @returns Distance in kilometers
 */
export function haversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
): number {
  const R = 6371; // Earth radius in km

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

/**
 * Calculate minimum possible RTT for a given distance
 * Uses fiber optic speed and accounts for round trip
 *
 * @param distanceKm - Distance in kilometers
 * @returns Minimum possible RTT in milliseconds
 */
function minPossibleRttMs(distanceKm: number): number {
  const oneWayMs = distanceKm / FIBER_SPEED_KM_PER_MS;
  return oneWayMs * 2; // Round trip
}

/**
 * Check if RTT is faster than physically possible (FTL violation)
 *
 * @param lat - Claimed latitude
 * @param lon - Claimed longitude
 * @param rttMs - Observed RTT in milliseconds
 * @returns true if RTT is impossibly fast
 */
function isFasterThanLight(lat: number, lon: number, rttMs: number): boolean {
  const distance = haversineDistance(
    lat,
    lon,
    SERVER_LOCATION.lat,
    SERVER_LOCATION.lon,
  );
  const minRtt = minPossibleRttMs(distance);

  // FTL if RTT is less than minimum with tolerance
  return rttMs < minRtt * FTL_TOLERANCE;
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
 * Detect network anomalies including FTL violations and timezone mismatches
 *
 * @param fingerprint - Normalized fingerprint with timezone
 * @param raw - Raw payload (unused for network detection)
 * @param sigint - Signal intelligence data with geo and tcpProbe
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

  // FTL Detection - requires geo.lat, geo.lon, and tcpProbe.rttMs
  if (
    sigint.geo?.lat !== undefined &&
    sigint.geo?.lon !== undefined &&
    sigint.tcpProbe?.rttMs !== undefined
  ) {
    const lat = sigint.geo.lat;
    const lon = sigint.geo.lon;
    const rttMs = sigint.tcpProbe.rttMs;

    if (isFasterThanLight(lat, lon, rttMs)) {
      const distance = haversineDistance(
        lat,
        lon,
        SERVER_LOCATION.lat,
        SERVER_LOCATION.lon,
      );
      const minRtt = minPossibleRttMs(distance);

      signals.push(
        createSignal(
          "NETWORK",
          AnomalyCodes.FTL_VIOLATION,
          0.95,
          `RTT >= ${minRtt.toFixed(1)}ms (distance: ${distance.toFixed(0)}km)`,
          `RTT = ${rttMs}ms (impossibly fast)`,
          ["sigint.geo.lat", "sigint.geo.lon", "sigint.tcpProbe.rttMs"],
        ),
      );
    }
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
