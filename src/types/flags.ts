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
  // IP/ASN history flags
  /** Device appeared on a new ASN not seen in its IP history */
  NEW_ASN_FOR_DEVICE: "new_asn_for_device",
  /** Device cycling through excessive unique IPs (>=100 in 24h) */
  IP_CHURN: "ip_churn",
  /** Timezone offset vs independently computed offset mismatch */
  TZ_OFFSET_COMPUTED_MISMATCH: "tz_offset_computed_mismatch",
  /** CSS media properties differ between getComputedStyle and matchMedia APIs */
  CSS_MEDIA_API_MISMATCH: "css_media_api_mismatch",
  /** JS/layout engine detected from errors doesn't match UA claim */
  ENGINE_MISMATCH: "engine_mismatch",
  /** WebRTC public IP doesn't match TCP/TLS connection IP */
  WEBRTC_IP_MISMATCH: "webrtc_ip_mismatch",
  /** screen.colorDepth !== screen.pixelDepth */
  SCREEN_DEPTH_MISMATCH: "screen_depth_mismatch",
  /** screen.availWidth/Height exceeds screen.width/height */
  SCREEN_AVAIL_OVERFLOW: "screen_avail_overflow",
  /** CSS device-screen string doesn't match screen.width/height */
  DEVICE_SCREEN_STRING_MISMATCH: "device_screen_string_mismatch",
  /** CSS device-aspect-ratio doesn't match screen dimensions */
  ASPECT_RATIO_MISMATCH: "aspect_ratio_mismatch",
  /** Worker scope locale/language/timezone differs across scopes */
  WORKER_LOCALE_MISMATCH: "worker_locale_mismatch",
  /** Incognito detector's browser identification doesn't match UA */
  INCOGNITO_BROWSER_MISMATCH: "incognito_browser_mismatch",

  // JA4/H2 coherence flags
  /** TLS library doesn't exist on claimed OS */
  TLS_PLATFORM_MISMATCH: "tls_platform_mismatch",
  /** TLS library doesn't match claimed browser */
  TLS_BROWSER_MISMATCH: "tls_browser_mismatch",
  /** H2 pseudo-header order conflicts with TLS cipher hash */
  H2_TLS_MISMATCH: "h2_tls_mismatch",
  /** QUIC from claimed iOS device (informational VPN indicator) */
  QUIC_IOS_VPN: "quic_ios_vpn",
  /** No ALPN but UA claims a modern browser */
  NO_ALPN_BROWSER: "no_alpn_browser",
} as const;

/** Union type of all device flag values. */
export type DeviceFlag = (typeof DeviceFlags)[keyof typeof DeviceFlags];
