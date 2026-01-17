// src/services/profile/flag-computation.ts
// AR-120: Extracted flag computation logic from profile-service.ts
import { Fingerprint, DeviceProfile, DeviceFlags } from "./types";

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
  // Anomaly detection weights (AR-141)
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
  /** Faster-than-light network violation */
  [DeviceFlags.FTL_VIOLATION]: 0.35,
  /** IP-based timezone mismatch */
  [DeviceFlags.IP_TIMEZONE_MISMATCH]: 0.1,
  /** Server vs client timezone mismatch */
  [DeviceFlags.SERVER_CLIENT_TZ_MISMATCH]: 0.12,
  /** Math engine doesn't match claimed browser */
  [DeviceFlags.MATH_ENGINE_MISMATCH]: 0.25,
} as const;

/**
 * Detect bot-like signals in fingerprint
 * Returns array of detected bot flags
 */
export function detectBotSignals(fingerprint: Fingerprint): string[] {
  const flags: string[] = [];

  // SwiftShader is a software renderer commonly used by headless browsers
  if (fingerprint.gpu_renderer?.toLowerCase().includes("swiftshader")) {
    flags.push(DeviceFlags.HEADLESS_BROWSER);
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  // Very small viewport (800x600) is typical of automated browsers
  if (fingerprint.screen_dims === "800x600") {
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  // Check user agent for bot patterns
  if (fingerprint.user_agent) {
    const ua = fingerprint.user_agent.toLowerCase();
    if (
      ua.includes("bot") ||
      ua.includes("crawler") ||
      ua.includes("spider") ||
      ua.includes("headless")
    ) {
      flags.push(DeviceFlags.BOT_DETECTED);
    }
  }

  // Single CPU core and very low memory are atypical for real devices
  if (
    fingerprint.hardware_concurrency === 1 &&
    fingerprint.device_memory !== undefined &&
    fingerprint.device_memory < 1
  ) {
    flags.push(DeviceFlags.BOT_DETECTED);
  }

  // Remove duplicates
  return [...new Set(flags)];
}

/**
 * Compute all flags for a profile based on fingerprint and profile state
 */
export function computeFlags(
  fingerprint: Fingerprint,
  existingProfile: DeviceProfile | null,
  isNewDevice: boolean,
  hasDrift: boolean,
): string[] {
  const flags: string[] = [];

  // NEW_DEVICE flag for first-time devices
  if (isNewDevice) {
    flags.push(DeviceFlags.NEW_DEVICE);
  }

  // Bot detection flags
  const botFlags = detectBotSignals(fingerprint);
  flags.push(...botFlags);

  // FINGERPRINT_MISMATCH flag when significant drift is detected
  if (existingProfile && hasDrift) {
    flags.push(DeviceFlags.FINGERPRINT_MISMATCH);
  }

  // RAPID_REQUESTS flag - check if request rate is suspicious
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

  // Remove duplicates and return
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
  // Treat as new device if explicitly marked or no existing profile
  const effectivelyNewDevice = isNewDevice || existingProfile === null;

  // Start with base risk
  let riskScore = effectivelyNewDevice
    ? RISK_WEIGHTS.BASE_NEW_DEVICE
    : RISK_WEIGHTS.BASE_RETURNING;

  // Apply flag-based adjustments using lookup table
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

  // Clamp to valid range [0, 1]
  return Math.max(0, Math.min(1, riskScore));
}
