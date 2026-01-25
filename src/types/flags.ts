/**
 * Device flags for risk assessment.
 *
 * Canonical set of flags used by both matching and profile services.
 * Flags are categorized by signal type: neutral, positive, negative, and anomaly.
 */
export const DeviceFlags = {
  // Neutral signals
  /** Device was just created during this session */
  NEW_DEVICE: "new_device",

  // Positive signals
  /** Device has been verified through additional authentication */
  VERIFIED: "verified",
  /** Device has been seen in previous sessions */
  RETURNING_USER: "returning_user",

  // Negative signals
  /** Automated bot behavior detected */
  BOT_DETECTED: "bot_detected",
  /** Headless browser environment detected */
  HEADLESS_BROWSER: "headless_browser",
  /** Fingerprint doesn't match stored profile */
  FINGERPRINT_MISMATCH: "fingerprint_mismatch",
  /** Unusually high request rate from device */
  RAPID_REQUESTS: "rapid_requests",

  // Anomaly detection flags
  /** Navigator properties have been tampered with */
  NAVIGATOR_LIES: "navigator_lies",
  /** Traffic likely routed through proxy */
  LIKELY_PROXY: "likely_proxy",
  /** Traffic likely routed through VPN */
  LIKELY_VPN: "likely_vpn",
  /** Web Worker environment doesn't match main thread */
  WORKER_MISMATCH: "worker_mismatch",
  /** Screen dimensions don't match CSS media queries */
  SCREEN_CSS_MISMATCH: "screen_css_mismatch",
  /** IP geolocation doesn't match reported timezone */
  IP_TIMEZONE_MISMATCH: "ip_timezone_mismatch",
  /** Server-side and client-side timezone don't match */
  SERVER_CLIENT_TZ_MISMATCH: "server_client_tz_mismatch",
} as const;

/** Union type of all device flag values. */
export type DeviceFlag = (typeof DeviceFlags)[keyof typeof DeviceFlags];
