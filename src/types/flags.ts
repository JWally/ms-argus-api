// src/types/flags.ts

/**
 * Device flags for risk assessment
 * Used by both matching and profile services
 */
export const DeviceFlags = {
  // Neutral signals
  NEW_DEVICE: "new_device",
  // Positive signals
  VERIFIED: "verified",
  RETURNING_USER: "returning_user",
  // Negative signals
  BOT_DETECTED: "bot_detected",
  HEADLESS_BROWSER: "headless_browser",
  FINGERPRINT_MISMATCH: "fingerprint_mismatch",
  RAPID_REQUESTS: "rapid_requests",
} as const;

export type DeviceFlag = (typeof DeviceFlags)[keyof typeof DeviceFlags];
