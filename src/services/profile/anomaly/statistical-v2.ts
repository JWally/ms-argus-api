/**
 * Statistical Anomaly Detection V2 using Shannon Scoring.
 *
 * Detects fingerprint anomalies using:
 * - Shannon self-information (surprise) scoring
 * - Bayesian blending between UA-specific and global baselines
 * - Config-driven fingerprint analysis (extensible via fingerprint-analysis.ts)
 * - Cross-signal correlation for combined anomaly detection
 * - Per-fingerprint-type configuration for different cardinality profiles
 *
 * Key features:
 * - Configurable grouping strategy (full UA string, browser family, ASN, etc.)
 * - Different thresholds for high vs low cardinality fingerprints
 * - Combined scoring when multiple signals are slightly anomalous
 * - Easy to add new fingerprint types via config
 *
 * @module services/profile/anomaly/statistical-v2
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import type { Fingerprint } from "../../../types/fingerprint";
import { parseUAFamily } from "../../../helpers/ua-family";
import { getByPath } from "../../../helpers/get-by-path";
import {
  recordFingerprintV2,
  fetchStatisticalV2Data,
  isStatisticalV2Enabled,
} from "../../cache";
import {
  AnomalyCodes,
  createSignal,
  type AnomalySignal,
  type AnomalyCode,
} from "./types";
import { buildRuleContext, evaluateBaselineRules } from "./baseline-rules";
import {
  FINGERPRINT_DEFINITIONS,
  getFingerprintTypes,
  getGroupingStrategy,
  COMBINED_THRESHOLD,
  COMBINED_MIN_CONFIDENCE,
  type FingerprintDefinition,
  type GroupingStrategy,
} from "../../../config/fingerprint-analysis";

const logger = new Logger({
  serviceName:
    process.env.POWERTOOLS_SERVICE_NAME || "argus-statistical-v2-detector",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

// ============================================================================
// Types
// ============================================================================

/** Score result for a single fingerprint type */
export interface FingerprintScore {
  /** Fingerprint type identifier (e.g., 'ja4', 'h2') */
  type: string;
  /** Grouping key used for baseline (e.g., 'chrome', 'AS20141', 'US') */
  groupingKey: string;
  /** Blended Shannon score [0, 1] where 1 = maximum surprise */
  score: number;
  /** Confidence in baseline data [0, 1] */
  confidence: number;
  /** Raw baseline-specific score before blending */
  rawUaScore: number;
  /** Raw global score before blending */
  rawGlobalScore: number;
  /** Sample count for baseline-specific data */
  uaTotal: number;
  /** Sample count for global data */
  globalTotal: number;
  /** Count of this specific fingerprint for baseline */
  uaCount: number;
  /** Count of this specific fingerprint globally */
  globalCount: number;
}

/** Context for statistical v2 detection (pre-fetched) */
export interface StatisticalContextV2 {
  /** Browser family extracted from User-Agent (e.g., 'chrome', 'firefox') */
  uaFamily: string;
  /** Original User-Agent for logging */
  originalUA: string | null;
  /** Extracted fingerprint values keyed by type */
  fingerprints: Record<string, string | null>;
  /** Grouping keys used for each fingerprint type */
  groupingKeys: Record<string, string>;
  /** Score data for each fingerprint type */
  scores: Record<string, FingerprintScore | null>;
  /** Combined anomaly score (if multiple signals present) */
  combinedScore: number | null;
  /** True if baseline recording was skipped due to rule match */
  baselineSkipped?: boolean;
  /** IDs of baseline rules that matched (empty if none) */
  matchedRules?: string[];
}

/** Raw network data from sigint payload */
export interface RawNetworkData {
  tlsFingerprint?: {
    ja4?: string | null;
  } | null;
  h2Probe?: {
    h2_fingerprint?: {
      fingerprint?: string | null;
    } | null;
  } | null;
  tcpProbe?: {
    user_agent?: string | null;
  } | null;
}

// ============================================================================
// Scoring Functions
// ============================================================================

/**
 * Compute Shannon self-information (surprise) score.
 *
 * Shannon surprise = -log₂(P) where P = count/total
 *
 * Intuition:
 * - Common events (P=50%) have low surprise (~1 bit)
 * - Rare events (P=1%) have high surprise (~6.6 bits)
 * - Very rare events (P=0.01%) have very high surprise (~13.3 bits)
 *
 * We normalize against maxSurpriseBits to get a [0, 1] score.
 *
 * @param count - Number of observations for this value
 * @param total - Total observations
 * @param maxBits - Ceiling for normalization (type-specific)
 * @returns Score in [0, 1] where 1 = maximum surprise (anomalous)
 */
export function computeShannonScore(
  count: number,
  total: number,
  maxBits: number,
): number {
  if (total === 0) {
    return 0.5; // Neutral if no data
  }
  if (count === 0) {
    return 1.0; // Maximum surprise for unseen value
  }

  const p = count / total;
  const surpriseBits = -Math.log2(p);

  return Math.min(1.0, surpriseBits / maxBits);
}

/**
 * Compute confidence in UA-specific data based on sample size.
 *
 * Uses sqrt curve which matches statistical intuition:
 * - Standard error ∝ 1/√N
 * - Early samples matter more than later ones
 * - Plateaus at "enough" samples (type-specific threshold)
 *
 * @param sampleCount - Number of observations for this UA family
 * @param saturationThreshold - Samples needed for 100% confidence
 * @returns Confidence in [0, 1]
 */
export function computeConfidence(
  sampleCount: number,
  saturationThreshold: number,
): number {
  return Math.min(1.0, Math.sqrt(sampleCount / saturationThreshold));
}

/**
 * Compute blended anomaly score using Bayesian approach.
 *
 * Smoothly transitions from global baseline (for new UA families) to
 * UA-specific baseline (for established UA families) based on sample size.
 *
 * Formula: final = (ua_score × confidence) + (global_score × (1 - confidence))
 *
 * @param uaCount - Count for this fingerprint within UA family
 * @param uaTotal - Total observations for UA family
 * @param globalCount - Count across all UA families
 * @param globalTotal - Total global observations
 * @param definition - Fingerprint type definition with tuning parameters
 * @returns Blended score with confidence and raw values
 */
export function computeBlendedScore(
  uaCount: number,
  uaTotal: number,
  globalCount: number,
  globalTotal: number,
  definition: FingerprintDefinition,
): {
  score: number;
  confidence: number;
  rawUaScore: number;
  rawGlobalScore: number;
} {
  const confidence = computeConfidence(uaTotal, definition.saturationThreshold);
  const rawUaScore = computeShannonScore(
    uaCount,
    uaTotal,
    definition.maxSurpriseBits,
  );
  const rawGlobalScore = computeShannonScore(
    globalCount,
    globalTotal,
    definition.maxSurpriseBits,
  );

  // Bayesian blend:
  // - confidence=0 (new UA): 100% global score
  // - confidence=1 (established UA): 100% UA-specific score
  const score = rawUaScore * confidence + rawGlobalScore * (1 - confidence);

  return { score, confidence, rawUaScore, rawGlobalScore };
}

/**
 * Compute combined anomaly score from multiple signals.
 *
 * Uses probability of "at least one anomaly" formula:
 * combined = 1 - ∏(1 - score_i)
 *
 * This captures the intuition that two weak signals are suspicious:
 * - JA4=0.5, H2=0.5 → combined=0.75 (suspicious!)
 * - JA4=0.8, H2=0.0 → combined=0.80 (single strong signal)
 *
 * Only includes signals with sufficient confidence.
 *
 * @param scores - Array of fingerprint scores
 * @param minConfidence - Minimum confidence to include a score
 * @returns Combined score, or null if insufficient data
 */
export function computeCombinedScore(
  scores: (FingerprintScore | null)[],
  minConfidence: number,
): number | null {
  const validScores = scores.filter(
    (s): s is FingerprintScore => s !== null && s.confidence >= minConfidence,
  );

  if (validScores.length < 2) {
    return null; // Need at least 2 signals for combined scoring
  }

  // P(at least one anomaly) = 1 - P(all normal)
  const pAllNormal = validScores.reduce((acc, s) => acc * (1 - s.score), 1);
  return 1 - pAllNormal;
}

// ============================================================================
// Grouping Key Resolution
// ============================================================================

/**
 * Resolve a single grouping key component (built-in name or path).
 */
function resolveSingleKey(
  key: string,
  uaFamily: string,
  network: RawNetworkData | undefined,
  device: Record<string, Record<string, unknown> | undefined> | undefined,
  originalUA: string | null,
): string | null {
  // Handle built-in strategy names
  switch (key) {
    case "uaFamily":
      return uaFamily;
    case "userAgent":
      // Return full user-agent string for precise grouping
      return originalUA;
    case "asn": {
      const asn = getByPath<string | number>(
        network as Record<string, unknown>,
        "tlsFingerprint.asn",
      );
      return asn ? `AS${asn}` : null;
    }
    case "country":
      return (
        getByPath<string>(
          network as Record<string, unknown>,
          "tlsFingerprint.country",
        ) || null
      );
    case "platform":
      return (
        getByPath<string>(
          device as Record<string, unknown>,
          "navigator.platform",
        ) || null
      );
    case "gpu":
      return (
        getByPath<string>(
          device as Record<string, unknown>,
          "canvasWebgl.gpu.compressedGPU",
        ) || null
      );
    case "cpuCores":
      const cores = getByPath<number>(
        device as Record<string, unknown>,
        "workerScope.hardwareConcurrency",
      );
      return cores ? String(cores) : null;
    case "deviceMemory":
      const mem = getByPath<number>(
        device as Record<string, unknown>,
        "workerScope.deviceMemory",
      );
      return mem ? String(mem) : null;
    case "screen":
      const w = getByPath<number>(
        device as Record<string, unknown>,
        "screen.width",
      );
      const h = getByPath<number>(
        device as Record<string, unknown>,
        "screen.height",
      );
      return w && h ? `${w}x${h}` : null;
    default:
      // Treat as a path - try network first, then device
      let value = getByPath<string | number>(
        network as Record<string, unknown>,
        key,
      );
      if (value === undefined || value === null) {
        value = getByPath<string | number>(
          device as Record<string, unknown>,
          key,
        );
      }
      return value !== undefined && value !== null ? String(value) : null;
  }
}

/**
 * Resolve the grouping key for a fingerprint type based on its strategy.
 *
 * @param strategy - The grouping strategy from config
 * @param uaFamily - Pre-parsed UA family (for "uaFamily" strategy)
 * @param network - Network payload (for ASN, country, etc.)
 * @param device - Device payload (for custom paths)
 * @param originalUA - Original user-agent string (for "userAgent" strategy)
 * @returns The resolved grouping key, or null if it can't be resolved
 */
function resolveGroupingKeyWithUA(
  strategy: GroupingStrategy,
  uaFamily: string,
  network: RawNetworkData | undefined,
  device: Record<string, Record<string, unknown> | undefined> | undefined,
  originalUA: string | null,
): string | null {
  // Handle composite keys (array of keys/paths)
  if (Array.isArray(strategy)) {
    const parts: string[] = [];
    for (const key of strategy) {
      const value = resolveSingleKey(
        key,
        uaFamily,
        network,
        device,
        originalUA,
      );
      if (value) {
        parts.push(value);
      }
    }
    return parts.length > 0 ? parts.join(":") : null;
  }

  // Handle single key (built-in name or path)
  return resolveSingleKey(strategy, uaFamily, network, device, originalUA);
}

// Old resolveGroupingKey removed - use resolveGroupingKeyWithUA instead

// ============================================================================
// Context Fetching
// ============================================================================

/**
 * Extract all configured fingerprints from the network payload.
 *
 * @param network - Raw network data from sigint
 * @returns Map of fingerprint type to extracted value (or null if not present)
 */
function extractFingerprints(
  network: RawNetworkData | undefined,
): Record<string, string | null> {
  const result: Record<string, string | null> = {};

  if (!network) {
    for (const type of getFingerprintTypes()) {
      result[type] = null;
    }
    return result;
  }

  for (const [type, definition] of Object.entries(FINGERPRINT_DEFINITIONS)) {
    const value = getByPath<string>(
      network as Record<string, unknown>,
      definition.path,
    );
    result[type] = value || null;
  }

  return result;
}

/**
 * Fetch statistical v2 context for anomaly detection.
 *
 * This async function should be called early in the request pipeline
 * to pre-fetch data from Valkey. The returned context is then passed
 * to the sync detectStatisticalAnomaliesV2 function.
 *
 * @param fingerprint - Fingerprint data containing user_agent
 * @param network - Raw network data containing fingerprints
 * @param device - Raw device payload for baseline rule evaluation
 * @returns Statistical context or null if detection is disabled/not applicable
 */
export async function fetchStatisticalContextV2(
  fingerprint: Fingerprint,
  network: RawNetworkData | undefined,
  device?: Record<string, Record<string, unknown> | undefined>,
): Promise<StatisticalContextV2 | null> {
  if (!isStatisticalV2Enabled()) {
    logger.debug("Statistical v2 disabled");
    return null;
  }

  // Extract user agent
  const userAgent =
    fingerprint.user_agent || network?.tcpProbe?.user_agent || null;
  if (!userAgent) {
    logger.warn("Statistical v2 skipped - no user agent");
    return null;
  }

  // Parse UA into family (chrome, firefox, safari, etc.) - NOT full string
  const uaParsed = parseUAFamily(userAgent);
  const uaFamily = uaParsed.baselineKey;

  logger.debug("UA family parsed", {
    original: userAgent.substring(0, 60),
    browser: uaParsed.browser,
    majorVersion: uaParsed.majorVersion,
    baselineKey: uaFamily,
  });

  // Extract all configured fingerprints
  const fingerprints = extractFingerprints(network);

  // Check if we have at least one fingerprint
  const hasAnyFingerprint = Object.values(fingerprints).some((v) => v !== null);
  if (!hasAnyFingerprint) {
    logger.debug("Statistical v2 skipped - no fingerprints available");
    return null;
  }

  // Resolve grouping keys for each fingerprint type
  const types = getFingerprintTypes();
  const groupingKeys: Record<string, string> = {};

  for (const type of types) {
    const strategy = getGroupingStrategy(type);
    const key = resolveGroupingKeyWithUA(
      strategy,
      uaFamily,
      network,
      device,
      userAgent,
    );
    // Fall back to uaFamily if the custom key can't be resolved
    groupingKeys[type] = key || uaFamily;
  }

  try {
    // Evaluate baseline filtering rules
    const ruleContext = buildRuleContext(fingerprint, device);
    const ruleResult = evaluateBaselineRules(ruleContext);
    const skipBaseline = ruleResult.shouldSkipBaseline;

    if (skipBaseline) {
      logger.info("Skipping baseline update", {
        uaFamily,
        matchedRules: ruleResult.matchedRules,
      });
      metrics.addMetric("BaselineSkipped", MetricUnit.Count, 1);
    }

    // Branch: read-only (skip) vs read+write (record)
    const fetcher = skipBaseline ? fetchStatisticalV2Data : recordFingerprintV2;

    // Fetch data for all fingerprint types in parallel (using per-type grouping keys)
    const dataPromises = types.map((type) => {
      const value = fingerprints[type];
      const groupKey = groupingKeys[type];
      if (!value) return Promise.resolve(null);
      return fetcher(groupKey, type, value);
    });

    const dataResults = await Promise.all(dataPromises);

    // Compute scores for each fingerprint type
    const scores: Record<string, FingerprintScore | null> = {};

    for (let i = 0; i < types.length; i++) {
      const type = types[i];
      const data = dataResults[i];
      const value = fingerprints[type];
      const definition = FINGERPRINT_DEFINITIONS[type];
      const groupKey = groupingKeys[type];

      if (!data || !value || !definition) {
        scores[type] = null;
        continue;
      }

      const blended = computeBlendedScore(
        data.count,
        data.total,
        data.globalCount,
        data.globalTotal,
        definition,
      );

      scores[type] = {
        type,
        groupingKey: groupKey,
        score: blended.score,
        confidence: blended.confidence,
        rawUaScore: blended.rawUaScore,
        rawGlobalScore: blended.rawGlobalScore,
        uaTotal: data.total,
        globalTotal: data.globalTotal,
        uaCount: data.count,
        globalCount: data.globalCount,
      };

      // Emit metric for this fingerprint type
      const metricName = `StatisticalV2${capitalize(type)}Score`;
      metrics.addMetric(metricName, MetricUnit.NoUnit, blended.score);
    }

    // Compute combined score from all available scores
    const combinedScore = computeCombinedScore(
      Object.values(scores),
      COMBINED_MIN_CONFIDENCE,
    );

    // Log context summary
    const scoresSummary: Record<string, string | undefined> = {};
    const confidenceSummary: Record<string, string | undefined> = {};
    for (const [type, score] of Object.entries(scores)) {
      if (score) {
        scoresSummary[type] = score.score.toFixed(3);
        confidenceSummary[`${type}Confidence`] = score.confidence.toFixed(3);
      }
    }

    logger.info("Statistical v2 context fetched", {
      uaFamily,
      ...scoresSummary,
      ...confidenceSummary,
      combinedScore: combinedScore?.toFixed(3),
      baselineSkipped: skipBaseline,
    });

    return {
      uaFamily,
      originalUA: userAgent,
      fingerprints,
      groupingKeys,
      scores,
      combinedScore,
      baselineSkipped: skipBaseline,
      matchedRules: ruleResult.matchedRules,
    };
  } catch (error) {
    logger.warn("Statistical v2 context fetch failed", { error, uaFamily });
    metrics.addMetric("StatisticalV2ContextError", MetricUnit.Count, 1);
    return null;
  }
}

// ============================================================================
// Detection
// ============================================================================

/**
 * Detect statistical anomalies from pre-fetched v2 context.
 *
 * Detection strategy:
 * 1. Check each fingerprint independently with type-specific thresholds
 * 2. Check combined score for correlated weak signals
 * 3. Return all triggered anomalies with severity = score
 *
 * @param context - Pre-fetched statistical context, or null to skip detection
 * @returns Array of anomaly signals (empty if no anomalies detected)
 */
export function detectStatisticalAnomaliesV2(
  context: StatisticalContextV2 | null,
): AnomalySignal[] {
  if (!context) {
    return [];
  }

  const signals: AnomalySignal[] = [];
  const { uaFamily, scores, combinedScore } = context;

  // Check each fingerprint type with its specific thresholds
  for (const [type, score] of Object.entries(scores)) {
    if (!score) continue;

    const definition = FINGERPRINT_DEFINITIONS[type];
    if (!definition) continue;

    if (
      score.score >= definition.anomalyThreshold &&
      score.confidence >= definition.confidenceThreshold
    ) {
      logger.info(`Rare ${type.toUpperCase()} for UA detected`, {
        uaFamily,
        score: score.score.toFixed(3),
        threshold: definition.anomalyThreshold,
        confidence: score.confidence.toFixed(3),
        uaCount: score.uaCount,
        uaTotal: score.uaTotal,
      });

      const metricName = `StatisticalV2${capitalize(type)}Anomaly`;
      metrics.addMetric(metricName, MetricUnit.Count, 1);

      // Validate that the anomaly code exists
      const anomalyCode = definition.anomalyCode as AnomalyCode;
      if (!(anomalyCode in AnomalyCodes)) {
        logger.error(`Unknown anomaly code: ${anomalyCode}`);
        continue;
      }

      signals.push(
        createSignal("STATISTICAL", anomalyCode, score.score, {
          expected: `${definition.fieldName} typical for '${uaFamily}' (threshold=${definition.anomalyThreshold})`,
          actual: `score=${score.score.toFixed(3)}, seen=${score.uaCount}/${score.uaTotal}`,
          fields: [definition.fieldName, "user_agent"],
        }),
      );
    }
  }

  // Check combined score - catches correlated weak signals
  if (
    combinedScore !== null &&
    combinedScore >= COMBINED_THRESHOLD &&
    // Only flag combined if no individual signals already flagged
    signals.length === 0
  ) {
    const scoreSummary = Object.entries(scores)
      .filter(([, s]) => s !== null)
      .map(([type, s]) => `${type}=${s!.score.toFixed(3)}`)
      .join(", ");

    logger.info("Combined fingerprint anomaly detected", {
      uaFamily,
      combinedScore: combinedScore.toFixed(3),
      threshold: COMBINED_THRESHOLD,
      scores: scoreSummary,
    });

    metrics.addMetric("StatisticalV2CombinedAnomaly", MetricUnit.Count, 1);

    const fieldNames = Object.values(FINGERPRINT_DEFINITIONS)
      .map((d) => d.fieldName)
      .concat("user_agent");

    signals.push(
      createSignal(
        "STATISTICAL",
        AnomalyCodes.RARE_FINGERPRINT_COMBO,
        combinedScore,
        {
          expected: `Fingerprints typical for '${uaFamily}'`,
          actual: `combined=${combinedScore.toFixed(3)} (${scoreSummary})`,
          fields: fieldNames,
        },
      ),
    );
  }

  return signals;
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Capitalize first letter of a string.
 */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
