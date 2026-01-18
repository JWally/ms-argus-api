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
  // Anomaly detection flags (AR-141)
  NAVIGATOR_LIES: "navigator_lies",
  LIKELY_PROXY: "likely_proxy",
  LIKELY_VPN: "likely_vpn",
  WORKER_MISMATCH: "worker_mismatch",
  SCREEN_CSS_MISMATCH: "screen_css_mismatch",
  IP_TIMEZONE_MISMATCH: "ip_timezone_mismatch",
  SERVER_CLIENT_TZ_MISMATCH: "server_client_tz_mismatch",
} as const;

export type DeviceFlag = (typeof DeviceFlags)[keyof typeof DeviceFlags];
