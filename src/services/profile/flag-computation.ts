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
 */
export const RISK_WEIGHTS = {
  /** Base risk for new devices (neutral) */
  BASE_NEW_DEVICE: 0.5,
  /** Base risk for returning devices without flags */
  BASE_RETURNING: 0.3,
  /** Bot detection is a strong negative signal */
  BOT_DETECTED: 0.25,
  /** Headless browser is a strong negative signal */
  HEADLESS_BROWSER: 0.15,
  /** Fingerprint mismatch suggests device spoofing */
  FINGERPRINT_MISMATCH: 0.15,
  /** Rapid requests suggests automated behavior */
  RAPID_REQUESTS: 0.1,
  /** Verified devices get trust bonus */
  VERIFIED: -0.2,
  /** Returning users get slight trust bonus */
  RETURNING_USER: -0.1,
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

  // Apply flag-based adjustments
  for (const flag of flags) {
    switch (flag) {
      case DeviceFlags.BOT_DETECTED:
        riskScore += RISK_WEIGHTS.BOT_DETECTED;
        break;
      case DeviceFlags.HEADLESS_BROWSER:
        riskScore += RISK_WEIGHTS.HEADLESS_BROWSER;
        break;
      case DeviceFlags.FINGERPRINT_MISMATCH:
        riskScore += RISK_WEIGHTS.FINGERPRINT_MISMATCH;
        break;
      case DeviceFlags.RAPID_REQUESTS:
        riskScore += RISK_WEIGHTS.RAPID_REQUESTS;
        break;
      case DeviceFlags.VERIFIED:
        riskScore += RISK_WEIGHTS.VERIFIED;
        break;
      case DeviceFlags.RETURNING_USER:
        riskScore += RISK_WEIGHTS.RETURNING_USER;
        break;
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
