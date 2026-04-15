/**
 * Type of anomaly detected
 */
export type AnomalyType =
  | "CROSS_FIELD"
  | "NETWORK"
  | "HARDWARE"
  | "IDENTITY"
  | "STATISTICAL";

/**
 * Anomaly codes as const object for type-safe lookup
 */
export const AnomalyCodes = {
  // Cross-field anomalies
  NAVIGATOR_LIES: "NAVIGATOR_LIES",
  WORKER_MISMATCH: "WORKER_MISMATCH",
  SCREEN_CSS_MISMATCH: "SCREEN_CSS_MISMATCH",
  // Fingerprint signal anomalies
  HEADLESS_DETECTED: "HEADLESS_DETECTED",
  // Statistical anomalies
  RARE_FINGERPRINT_COMBO: "RARE_FINGERPRINT_COMBO",
  // Statistical v2 anomalies (Shannon scoring)
  RARE_JA4_FOR_UA: "RARE_JA4_FOR_UA",
  RARE_H2_FOR_UA: "RARE_H2_FOR_UA",
  RARE_MATHS_FOR_UA: "RARE_MATHS_FOR_UA",
  RARE_FONTS_FOR_UA: "RARE_FONTS_FOR_UA",
  RARE_LIES_FOR_UA: "RARE_LIES_FOR_UA",
  RARE_CSS_FOR_UA: "RARE_CSS_FOR_UA",
  RARE_TCP_MSS_FOR_UA: "RARE_TCP_MSS_FOR_UA",
  // IP/ASN history anomalies
  NEW_ASN_FOR_DEVICE: "NEW_ASN_FOR_DEVICE",
  IP_CHURN: "IP_CHURN",
  // Coherence anomalies (cross-signal Shannon scoring)
  RARE_LANG_FOR_TZ: "RARE_LANG_FOR_TZ",
  RARE_TZ_FOR_COUNTRY: "RARE_TZ_FOR_COUNTRY",
  RARE_ENGINE_COMBO: "RARE_ENGINE_COMBO",
  RARE_ENGINE_FOR_UA: "RARE_ENGINE_FOR_UA",
  // Statistical v2: cross-signal coherence (Shannon scoring)
  RARE_CSS_KEY_COUNT_FOR_UA: "RARE_CSS_KEY_COUNT_FOR_UA",
  RARE_CSS_IFACE_FOR_UA: "RARE_CSS_IFACE_FOR_UA",
  RARE_VENDOR_FOR_UA: "RARE_VENDOR_FOR_UA",
  RARE_FEATURE_PREFIX_FOR_UA: "RARE_FEATURE_PREFIX_FOR_UA",
  RARE_TIMING_FOR_UA: "RARE_TIMING_FOR_UA",
  RARE_WEBGL_VENDOR_FOR_UA: "RARE_WEBGL_VENDOR_FOR_UA",
  // Signal baseline anomalies (population-based learning)
  RARE_STACK_FORMAT_FOR_UA: "RARE_STACK_FORMAT_FOR_UA",
  RARE_EVAL_LENGTH_FOR_UA: "RARE_EVAL_LENGTH_FOR_UA",
  RARE_WINDOW_PREFIX_FOR_UA: "RARE_WINDOW_PREFIX_FOR_UA",
  RARE_WORKER_NAV_PROPS_FOR_UA: "RARE_WORKER_NAV_PROPS_FOR_UA",
  // Consistency anomalies (within-payload cross-signal checks)
  AUDIO_NOISE_DETECTED: "AUDIO_NOISE_DETECTED",
  TIMEZONE_OFFSET_MISMATCH: "TIMEZONE_OFFSET_MISMATCH",
  TOUCH_MISMATCH: "TOUCH_MISMATCH",
  WEBGL_RENDERER_MISMATCH: "WEBGL_RENDERER_MISMATCH",
  TZ_OFFSET_COMPUTED_MISMATCH: "TZ_OFFSET_COMPUTED_MISMATCH",
  CSS_MEDIA_API_MISMATCH: "CSS_MEDIA_API_MISMATCH",
  ENGINE_MISMATCH: "ENGINE_MISMATCH",
  WEBRTC_IP_MISMATCH: "WEBRTC_IP_MISMATCH",
  SCREEN_DEPTH_MISMATCH: "SCREEN_DEPTH_MISMATCH",
  SCREEN_AVAIL_OVERFLOW: "SCREEN_AVAIL_OVERFLOW",
  DEVICE_SCREEN_STRING_MISMATCH: "DEVICE_SCREEN_STRING_MISMATCH",
  ASPECT_RATIO_MISMATCH: "ASPECT_RATIO_MISMATCH",
  WORKER_LOCALE_MISMATCH: "WORKER_LOCALE_MISMATCH",
  INCOGNITO_BROWSER_MISMATCH: "INCOGNITO_BROWSER_MISMATCH",
  // JA4/H2 coherence (deterministic cross-signal checks)
  TLS_PLATFORM_MISMATCH: "TLS_PLATFORM_MISMATCH",
  TLS_BROWSER_MISMATCH: "TLS_BROWSER_MISMATCH",
  H2_TLS_MISMATCH: "H2_TLS_MISMATCH",
  QUIC_IOS_VPN: "QUIC_IOS_VPN",
  NO_ALPN_BROWSER: "NO_ALPN_BROWSER",
  // Timezone geolocation mismatch (CloudFront IP timezone vs client-reported)
  TZ_GEOLOCATION_MISMATCH: "TZ_GEOLOCATION_MISMATCH",
  // IP consistency across probes and WebRTC
  IP_PROBE_SCATTER: "IP_PROBE_SCATTER",
  WEBRTC_BLOCKED: "WEBRTC_BLOCKED",
  /**
   * WebRTC IP differs from the server-observed probe IPs, but all are on
   * the same /16 subnet. Strong indicator of CGNAT / cellular carrier
   * NAT (T-Mobile, Verizon, AT&T mobile, etc.) — not a proxy. Positive
   * signal rather than a suppressed mismatch; surfaced to downstream
   * consumers (dashboards, demo UI) so they can label the visitor as
   * mobile/CGNAT rather than showing nothing.
   */
  SAME_SUBNET_CGNAT: "SAME_SUBNET_CGNAT",
  /**
   * Client submitted WebRTC srflx candidates whose encrypted payload
   * failed HMAC verification against our shared STUN secret. This cannot
   * occur through normal browser/network paths — a legitimate client
   * talking to our STUN always returns a MAC-valid blob. Indicates
   * active forgery: mock STUN, MITM of our STUN response, or synthetic
   * candidate injection. High severity; no benign explanation.
   */
  WEBRTC_SIGINT_FORGERY: "WEBRTC_SIGINT_FORGERY",
  // Network probe anomalies (computed from tcp_info/rtt_fingerprint in the API)
  LIKELY_PROXY: "LIKELY_PROXY",
  LIKELY_VPN: "LIKELY_VPN",
} as const;

export type AnomalyCode = (typeof AnomalyCodes)[keyof typeof AnomalyCodes];

/**
 * Evidence structure for anomaly signals
 */
export interface AnomalyEvidence {
  expected: string;
  actual: string;
  fields?: string[];
}

/**
 * Individual anomaly signal
 */
export interface AnomalySignal {
  type: AnomalyType;
  code: AnomalyCode;
  severity: number; // 0-1, runtime clamped
  evidence: AnomalyEvidence;
}

/**
 * Aggregated result from all anomaly detectors
 */
export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number;
  suggestedFlags: string[];
}

/**
 * Helper to create signals with clamped severity
 */
export function createSignal(
  type: AnomalyType,
  code: AnomalyCode,
  severity: number,
  evidence: AnomalyEvidence,
): AnomalySignal {
  return {
    type,
    code,
    severity: Math.max(0, Math.min(1, severity)),
    evidence,
  };
}
