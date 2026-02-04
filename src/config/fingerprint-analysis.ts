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
export const FINGERPRINT_DEFINITIONS: Record<string, FingerprintDefinition> = {
  /**
   * JA4 TLS Fingerprint
   *
   * High cardinality - varies with browser extensions, TLS library versions.
   * Grouped by full user agent for precise baseline comparison.
   */
  ja4: {
    path: "tlsFingerprint.ja4",
    anomalyCode: "RARE_JA4_FOR_UA",
    fieldName: "ja4",
    groupBy: "userAgent",
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
   * Grouped by full user agent for precise baseline comparison.
   */
  h2: {
    path: "h2Probe.h2_fingerprint.fingerprint",
    anomalyCode: "RARE_H2_FOR_UA",
    fieldName: "http2_fingerprint",
    groupBy: "userAgent",
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
   * GPU Renderer
   *
   * Medium cardinality (28 unique) - strong hardware signal.
   * Grouped by platform since GPU is tightly coupled to OS.
   */
  gpu: {
    path: "canvasWebgl.gpu.compressedGPU",
    anomalyCode: "RARE_GPU_FOR_PLATFORM",
    fieldName: "gpu",
    source: "device",
    groupBy: "platform",
    maxSurpriseBits: parseFloat(process.env.STAT_V2_GPU_MAX_BITS || "10"),
    saturationThreshold: parseInt(
      process.env.STAT_V2_GPU_SATURATION || "200",
      10,
    ),
    anomalyThreshold: parseFloat(process.env.STAT_V2_GPU_THRESHOLD || "0.5"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_GPU_CONFIDENCE || "0.3",
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
    groupBy: "userAgent",
    // Very low cardinality - expect 1 hash per exact UA
    maxSurpriseBits: parseFloat(process.env.STAT_V2_MATHS_MAX_BITS || "6"),
    // Need fewer samples since it's so stable
    saturationThreshold: parseInt(
      process.env.STAT_V2_MATHS_SATURATION || "50",
      10,
    ),
    // Low threshold - any deviation is suspicious
    anomalyThreshold: parseFloat(process.env.STAT_V2_MATHS_THRESHOLD || "0.3"),
    confidenceThreshold: parseFloat(
      process.env.STAT_V2_MATHS_CONFIDENCE || "0.2",
    ),
  },
} as const;

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
