import { Fingerprint, DeviceProfile, DeviceFlags } from "./types";
import { detectAllAnomalies } from "./anomaly";

/**
 * Thresholds for flag computation
 */
export const FLAG_THRESHOLDS = {
  /** Requests per hour that triggers RAPID_REQUESTS flag */
  RAPID_REQUESTS_PER_HOUR: 50,
} as const;

/**
 * Risk score weights for different flags
 * Positive values increase risk, negative values decrease risk
 * Flag-based weights use the exact flag values as keys for lookup table pattern
 */
export const RISK_WEIGHTS = {
  /** Base risk for new devices (neutral) */
  BASE_NEW_DEVICE: 0.5,
  /** Base risk for returning devices without flags */
  BASE_RETURNING: 0.3,
  /** Bot detection is a strong negative signal */
  [DeviceFlags.BOT_DETECTED]: 0.25,
  /** Headless browser is a strong negative signal */
  [DeviceFlags.HEADLESS_BROWSER]: 0.15,
  /** Fingerprint mismatch suggests device spoofing */
  [DeviceFlags.FINGERPRINT_MISMATCH]: 0.15,
  /** Rapid requests suggests automated behavior */
  [DeviceFlags.RAPID_REQUESTS]: 0.1,
  /** Verified devices get trust bonus */
  [DeviceFlags.VERIFIED]: -0.2,
  /** Returning users get slight trust bonus */
  [DeviceFlags.RETURNING_USER]: -0.1,
  /** Navigator API tampering */
  [DeviceFlags.NAVIGATOR_LIES]: 0.15,
  /** High proxy likelihood */
  [DeviceFlags.LIKELY_PROXY]: 0.1,
  /** VPN usage detected */
  [DeviceFlags.LIKELY_VPN]: 0.05,
  /** Navigator/Worker scope mismatch */
  [DeviceFlags.WORKER_MISMATCH]: 0.2,
  /** Screen/CSS dimension mismatch */
  [DeviceFlags.SCREEN_CSS_MISMATCH]: 0.1,
  /** Device appeared on a new ASN (soft signal, many legit reasons) */
  [DeviceFlags.NEW_ASN_FOR_DEVICE]: 0.05,
  /** Device cycling through excessive unique IPs (strong negative signal) */
  [DeviceFlags.IP_CHURN]: 0.2,
} as const;

/**
 * Detect bot-like signals in fingerprint
 * Returns array of detected bot flags
 */

/** User agent patterns that indicate bot/crawler traffic */
const BOT_UA_PATTERNS = ["bot", "crawler", "spider", "headless"];

/**
 * Check if user agent matches known bot patterns
 * @param ua - User agent string to check
 * @returns True if bot pattern detected
 */
function hasBotUserAgent(ua: string | undefined): boolean {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  return BOT_UA_PATTERNS.some((pattern) => lower.includes(pattern));
}

/**
 * Detect bot-like signals in a fingerprint
 * Checks GPU renderer (SwiftShader), screen size, user agent, and hardware specs
 * @param fingerprint - The fingerprint to analyze
 * @returns Array of detected bot flag strings
 */
export function detectBotSignals(fingerprint: Fingerprint): string[] {
  const flags: string[] = [];

  if (fingerprint.gpu_renderer?.toLowerCase().includes("swiftshader")) {
    flags.push(DeviceFlags.HEADLESS_BROWSER, DeviceFlags.BOT_DETECTED);
  }

  if (fingerprint.screen_dims === "800x600") {
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  if (hasBotUserAgent(fingerprint.user_agent)) {
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  if (
    fingerprint.hardware_concurrency === 1 &&
    fingerprint.device_memory !== undefined &&
    fingerprint.device_memory < 1
  ) {
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  return [...new Set(flags)];
}

/**
 * Context for flag computation
 */
export interface FlagContext {
  /** Whether this is a newly created device */
  isNewDevice: boolean;
  /** Whether significant drift was detected from existing profile */
  hasDrift: boolean;
  /** Raw payload for cross-field anomaly detection */
  raw?: unknown;
}

/**
 * Compute all flags for a device based on fingerprint and history
 * Combines bot detection, anomaly detection, drift detection, and rate limiting
 * @param fingerprint - The current fingerprint
 * @param existingProfile - Existing device profile (null for new devices)
 * @param ctx - Context including new device flag, drift flag, and raw payload
 * @returns Array of flag strings (deduplicated)
 */
export function computeFlags(
  fingerprint: Fingerprint,
  existingProfile: DeviceProfile | null,
  ctx: FlagContext,
): string[] {
  const { isNewDevice, hasDrift, raw } = ctx;
  const flags: string[] = [];

  if (isNewDevice) {
    flags.push(DeviceFlags.NEW_DEVICE);
  }

  const botFlags = detectBotSignals(fingerprint);
  flags.push(...botFlags);

  const anomalyResult = detectAllAnomalies(fingerprint, raw);
  flags.push(...anomalyResult.suggestedFlags);

  if (existingProfile && hasDrift) {
    flags.push(DeviceFlags.FINGERPRINT_MISMATCH);
  }

  if (existingProfile) {
    const hoursSinceFirstSeen =
      (Date.now() - existingProfile.first_seen_at) / (1000 * 60 * 60);
    const requestsPerHour =
      hoursSinceFirstSeen > 0
        ? (existingProfile.request_count + 1) / hoursSinceFirstSeen
        : existingProfile.request_count + 1;

    if (requestsPerHour > FLAG_THRESHOLDS.RAPID_REQUESTS_PER_HOUR) {
      flags.push(DeviceFlags.RAPID_REQUESTS);
    }
  }

  // Preserve existing positive flags (VERIFIED, RETURNING_USER)
  if (existingProfile?.flags) {
    const positiveFlags = existingProfile.flags.filter(
      (f) => f === DeviceFlags.VERIFIED || f === DeviceFlags.RETURNING_USER,
    );
    flags.push(...positiveFlags);
  }

  return [...new Set(flags)];
}

/**
 * Compute risk score based on flags and profile history
 * Returns a value between 0 (trusted) and 1 (high risk)
 */
export function computeRiskScore(
  flags: string[],
  existingProfile: DeviceProfile | null,
  isNewDevice: boolean,
): number {
  const effectivelyNewDevice = isNewDevice || existingProfile === null;

  let riskScore = effectivelyNewDevice
    ? RISK_WEIGHTS.BASE_NEW_DEVICE
    : RISK_WEIGHTS.BASE_RETURNING;

  for (const flag of flags) {
    const weight = RISK_WEIGHTS[flag as keyof typeof RISK_WEIGHTS];
    if (weight !== undefined) {
      riskScore += weight;
    }
  }

  // For returning devices, blend with historical risk (weighted average)
  // This prevents risk from changing too dramatically on a single request
  if (existingProfile && !effectivelyNewDevice) {
    const historicalWeight = 0.3;
    riskScore =
      riskScore * (1 - historicalWeight) +
      existingProfile.risk_score * historicalWeight;
  }

  return Math.max(0, Math.min(1, riskScore));
}
