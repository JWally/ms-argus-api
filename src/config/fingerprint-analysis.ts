/**
 * Fingerprint Analysis Configuration
 *
 * Defines which fingerprints to track for statistical anomaly detection,
 * their extraction paths from the sigint payload, and tuning parameters.
 *
 * To add a new fingerprint type:
 * 1. Add an entry to FINGERPRINT_DEFINITIONS
 * 2. Add a corresponding anomaly code to AnomalyCodes in types.ts
 * 3. No other code changes required
 *
 * @module config/fingerprint-analysis
 */

/**
 * Grouping key strategy for bucketing fingerprints.
 *
 * - "uaFamily": Group by browser family (chrome, firefox, safari, etc.) - DEFAULT
 * - "userAgent": Group by full user-agent string (most precise)
 * - "asn": Group by Autonomous System Number (network identity)
 * - "country": Group by country code
 * - "platform": Group by OS platform
 * - string path: Extract grouping key from payload (e.g., "device.navigator.platform")
 * - string[]: Composite key from multiple paths (joined with ":")
 */
export type GroupingStrategy =
  | "uaFamily"
  | "userAgent"
  | "asn"
  | "country"
  | "platform"
  | string
  | string[];

/**
 * Configuration for a single fingerprint type.
 */
export interface FingerprintDefinition {
  /**
   * Dot-path to extract the fingerprint value.
   * e.g., "tlsFingerprint.ja4" extracts network?.tlsFingerprint?.ja4
   * For hashes source, use the hash key directly: "maths"
   */
  path: string;

  /**
   * Which payload section to extract from.
   * - "network": sigint/network data (ja4, h2, etc.) - DEFAULT
   * - "device": device fingerprint data (gpu, etc.)
   * - "hashes": pre-computed hashes (maths, etc.)
   */
  source?: "network" | "device" | "hashes";

  /**
   * Anomaly code to emit when this fingerprint is anomalous.
   * Must be defined in AnomalyCodes.
   */
  anomalyCode: string;

  /**
   * Human-readable field name for evidence/logging.
   */
  fieldName: string;

  /**
   * How to group/bucket this fingerprint for baseline comparison.
   *
   * Different fingerprints may benefit from different grouping strategies:
   * - H2 fingerprint is very stable per browser family → group by "uaFamily"
   * - JA4 varies more by exact browser version → could group by full UA or "uaFamily"
   * - MSS/network signals → might group by "asn" for network-level baselines
   *
   * @default "uaFamily"
   */
  groupBy?: GroupingStrategy;

  /**
   * Max surprise bits for Shannon score normalization.
   * Higher = more tolerant of rare values.
   *
   * - 10 bits: 1-in-1024 gets max score (low cardinality)
   * - 12 bits: 1-in-4096 gets max score
   * - 14 bits: 1-in-16384 gets max score (high cardinality)
   */
  maxSurpriseBits: number;

  /**
   * Sample count for 100% confidence in baseline.
   * Higher = blend with global longer, more conservative.
   */
  saturationThreshold: number;

  /**
   * Score threshold to flag as anomalous [0, 1].
   * Lower = more sensitive, more false positives.
   */
  anomalyThreshold: number;

  /**
   * Minimum confidence required to flag [0, 1].
   * Higher = need more samples before flagging.
   */
  confidenceThreshold: number;

  /**
   * Optional transform to convert a raw extracted value into a string for counting.
   * Use for numeric/continuous values that need discretization.
   * If not provided, the value is extracted as a string directly.
   */
  transform?: (value: unknown) => string | null;
}

/**
 * Fingerprint definitions for statistical analysis.
 *
 * Each key is the fingerprint type identifier used in:
 * - Valkey keys: stat:v2:{ua_family}:{type}:{fingerprint}
 * - Metrics: StatisticalV2{Type}Score, StatisticalV2{Type}Anomaly
 * - Logging
 *
 * Tuning guidelines:
 * - High cardinality (many unique values): higher maxBits, higher saturation, higher thresholds
 * - Low cardinality (few unique values): lower maxBits, lower saturation, lower thresholds
 */
/** Default composite grouping key: UA string + browser family + client-parsed browser identity */
const DEFAULT_GROUP_BY: string[] = [
  "userAgent",
  "uaFamily",
  "navigator.userAgentParsed",
];

export const FINGERPRINT_DEFINITIONS: Record<string, FingerprintDefinition> = {
  /**
   * JA4 TLS Fingerprint
   *
   * High cardinality - varies with browser extensions, TLS library versions.
   * Grouped by composite key (UA string + browser family) to detect UA spoofing.
   */
  ja4: {
    path: "tlsFingerprint.ja4",
    anomalyCode: "RARE_JA4_FOR_UA",
    fieldName: "ja4",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_JA4_MAX_BITS || "12"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_JA4_SATURATION || "500",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_JA4_THRESHOLD || "0.6"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_JA4_CONFIDENCE || "0.3",
    ),
  },

  /**
   * HTTP/2 Fingerprint
   *
   * Low cardinality - very stable per device class.
   * Grouped by composite key (UA string + browser family) to detect UA spoofing.
   */
  h2: {
    path: "h2Probe.h2_fingerprint.fingerprint",
    anomalyCode: "RARE_H2_FOR_UA",
    fieldName: "http2_fingerprint",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_H2_MAX_BITS || "8"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_H2_SATURATION || "100",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_H2_THRESHOLD || "0.4"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_H2_CONFIDENCE || "0.25",
    ),
  },

  /**
   * Math Hash
   *
   * VERY low cardinality - deterministic per JS engine/browser version.
   * Same exact UA string should ALWAYS produce same math hash.
   * Any deviation = spoofed UA or modified JS engine.
   *
   * This is a STRONG lie detection signal because:
   * - Math operations (sin, cos, etc.) produce deterministic floating point results
   * - Results vary by JS engine (V8 vs SpiderMonkey vs JavaScriptCore)
   * - Cannot be spoofed without patching the entire math library
   */
  maths: {
    path: "maths",
    anomalyCode: "RARE_MATHS_FOR_UA",
    fieldName: "maths_hash",
    source: "hashes",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_MATHS_MAX_BITS || "6"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_MATHS_SATURATION || "50",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_MATHS_THRESHOLD || "0.3"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_MATHS_CONFIDENCE || "0.2",
    ),
  },

  /**
   * Font Hash
   *
   * Medium cardinality - varies by OS and installed fonts.
   * Grouped by composite key to detect font enumeration spoofing.
   */
  fonts: {
    path: "fonts",
    anomalyCode: "RARE_FONTS_FOR_UA",
    fieldName: "fonts_hash",
    source: "hashes",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_FONTS_MAX_BITS || "10"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_FONTS_SATURATION || "100",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_FONTS_THRESHOLD || "0.5"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_FONTS_CONFIDENCE || "0.25",
    ),
  },

  /**
   * Lies Hash
   *
   * Low cardinality - detected browser lies/inconsistencies.
   * Legitimate browsers should have consistent lies patterns per UA.
   * Spoofing tools often produce inconsistent lies signatures.
   */
  lies: {
    path: "lies",
    anomalyCode: "RARE_LIES_FOR_UA",
    fieldName: "lies_hash",
    source: "hashes",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_LIES_MAX_BITS || "8"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_LIES_SATURATION || "50",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_LIES_THRESHOLD || "0.4"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_LIES_CONFIDENCE || "0.2",
    ),
  },

  /**
   * CSS Hash
   *
   * Medium cardinality - CSS feature detection varies by browser/OS.
   * Should be consistent for same UA string + browser family.
   */
  css: {
    path: "css",
    anomalyCode: "RARE_CSS_FOR_UA",
    fieldName: "css_hash",
    source: "hashes",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: parseFloat(process.env.STAT_V2_CSS_MAX_BITS || "10"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_CSS_SATURATION || "100",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_CSS_THRESHOLD || "0.5"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_CSS_CONFIDENCE || "0.25",
    ),
  },

  /**
   * TCP Maximum Segment Size
   *
   * Semi-discrete numeric value (1360, 1440, 1460, etc.).
   * Varies by OS, network path, and VPN/tunnel usage.
   * Grouped by UA + ASN since MSS depends on network path.
   */
  tcp_mss: {
    path: "tcpProbe.rtt_fingerprint.snd_mss",
    anomalyCode: "RARE_TCP_MSS_FOR_UA",
    fieldName: "tcp_mss",
    groupBy: [...DEFAULT_GROUP_BY, "asn"],
    transform: (value: unknown): string | null => {
      if (typeof value !== "number" || !Number.isFinite(value)) return null;
      return String(Math.round(value));
    },
    maxSurpriseBits: parseFloat(process.env.STAT_V2_MSS_MAX_BITS || "6"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_MSS_SATURATION || "50",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_MSS_THRESHOLD || "0.4"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_MSS_CONFIDENCE || "0.25",
    ),
  },

  // ── Coherence signals (cross-field Shannon scoring) ──────────────────

  /**
   * Language for Timezone
   *
   * Low cardinality - language tags per browser+timezone combo.
   * Catches spoofed locale: "cz-RU" from Chrome/America/Chicago → max surprise.
   * Handles "en" vs "en-US" gracefully since both are common in US TZs.
   * Grouped by UA identity + timezone to avoid false positives across locales.
   */
  lang_for_tz: {
    path: "workerScope.language",
    source: "device",
    anomalyCode: "RARE_LANG_FOR_TZ",
    fieldName: "language",
    groupBy: [...DEFAULT_GROUP_BY, "workerScope.timezoneLocation"],
    maxSurpriseBits: 6,
    saturationThreshold: 50,
    anomalyThreshold: 0.5,
    confidenceThreshold: 0.25,
  },

  /**
   * Timezone for Country
   *
   * Low cardinality - timezone IDs per browser+country combo.
   * Subsumes rule-based IP_TIMEZONE_MISMATCH with nuance:
   * Atlantic/Reykjavik from Chrome/US → rare → flagged.
   * America/New_York from Chrome/US → common → pass.
   * Grouped by UA identity + country to detect TZ spoofing per browser.
   */
  tz_for_country: {
    path: "workerScope.timezoneLocation",
    source: "device",
    anomalyCode: "RARE_TZ_FOR_COUNTRY",
    fieldName: "timezone",
    groupBy: [...DEFAULT_GROUP_BY, "country"],
    maxSurpriseBits: 8,
    saturationThreshold: 100,
    anomalyThreshold: 0.5,
    confidenceThreshold: 0.25,
  },

  /**
   * JS Engine for Layout Engine
   *
   * Very low cardinality - only ~3 valid combos exist.
   * SpiderMonkey + WebKit = 0 observations = max surprise.
   * V8 + Blink = extremely common = no flag.
   */
  js_engine_for_layout: {
    path: "consoleErrors.jsEngine",
    source: "device",
    anomalyCode: "RARE_ENGINE_COMBO",
    fieldName: "js_engine",
    groupBy: "consoleErrors.layoutEngine",
    maxSurpriseBits: 6,
    saturationThreshold: 50,
    anomalyThreshold: 0.4,
    confidenceThreshold: 0.2,
  },

  /**
   * Resistance Engine for UA
   *
   * Very low cardinality - Gecko engine claiming Chrome UA = max surprise.
   * Grouped by composite UA key to catch engine/UA mismatches.
   */
  engine_for_ua: {
    path: "resistance.engine",
    source: "device",
    anomalyCode: "RARE_ENGINE_FOR_UA",
    fieldName: "resistance_engine",
    groupBy: DEFAULT_GROUP_BY,
    maxSurpriseBits: 6,
    saturationThreshold: 50,
    anomalyThreshold: 0.4,
    confidenceThreshold: 0.2,
  },

  /**
   * TLS-to-TCP Timing Ratio
   *
   * Ratio of TLS handshake time to TCP RTT. Proxy/VPN adds extra
   * TLS hops, inflating this ratio. Bucketed in 1.5 increments.
   * Grouped by UA + ASN since ratio depends on network path.
   */
  tls_ratio: {
    path: "tcpProbe.rtt_fingerprint.tls_to_tcp_ratio",
    anomalyCode: "RARE_TLS_RATIO_FOR_UA",
    fieldName: "tls_to_tcp_ratio",
    groupBy: [...DEFAULT_GROUP_BY, "asn"],
    transform: (value: unknown): string | null => {
      if (typeof value !== "number" || !Number.isFinite(value)) return null;
      const bucket = Math.floor(value / 1.5) * 1.5;
      return `${bucket.toFixed(1)}-${(bucket + 1.5).toFixed(1)}`;
    },
    maxSurpriseBits: parseFloat(process.env.STAT_V2_TLS_RATIO_MAX_BITS || "6"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_TLS_RATIO_SATURATION || "50",
      10,
    ),
    anomalyThreshold: parseFloat(
      process.env.STAT_V2_TLS_RATIO_THRESHOLD || "0.4",
    ),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_TLS_RATIO_CONFIDENCE || "0.25",
    ),
  },
};

/**
 * Get all defined fingerprint type keys.
 */
export function getFingerprintTypes(): string[] {
  return Object.keys(FINGERPRINT_DEFINITIONS);
}

/**
 * Get the grouping strategy for a fingerprint type.
 * Defaults to "uaFamily" if not specified.
 */
export function getGroupingStrategy(type: string): GroupingStrategy {
  return FINGERPRINT_DEFINITIONS[type]?.groupBy ?? "uaFamily";
}

/**
 * Combined score threshold.
 * When multiple fingerprints are slightly anomalous, flag if combined exceeds this.
 */
export const COMBINED_THRESHOLD = parseFloat(
  process.env.STAT_V2_COMBINED_THRESHOLD || "0.65",
);

/**
 * Minimum confidence for combined scoring.
 * All signals need at least this confidence to contribute.
 */
export const COMBINED_MIN_CONFIDENCE = parseFloat(
  process.env.STAT_V2_COMBINED_MIN_CONFIDENCE || "0.3",
);

/**
 * Minimum individual score to contribute to combined scoring.
 * Prevents low-scoring (common) signals from accumulating into
 * false positives via the product formula when many signals are present.
 * Score of 0.15 ≈ 1.8 bits surprise ≈ 29% probability — quite common.
 */
export const COMBINED_MIN_SCORE = parseFloat(
  process.env.STAT_V2_COMBINED_MIN_SCORE || "0.15",
);
