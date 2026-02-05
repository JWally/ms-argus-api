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

/** Input for blended score computation */
interface BlendedScoreInput {
  uaCount: number;
  uaTotal: number;
  globalCount: number;
  globalTotal: number;
  definition: FingerprintDefinition;
}

/** Output from blended score computation */
interface BlendedScoreResult {
  score: number;
  confidence: number;
  rawUaScore: number;
  rawGlobalScore: number;
}

/**
 * Compute blended anomaly score using Bayesian approach.
 *
 * Smoothly transitions from global baseline (for new UA families) to
 * UA-specific baseline (for established UA families) based on sample size.
 *
 * Formula: final = (ua_score × confidence) + (global_score × (1 - confidence))
 */
export function computeBlendedScore(
  input: BlendedScoreInput,
): BlendedScoreResult {
  const { uaCount, uaTotal, globalCount, globalTotal, definition } = input;
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

/** Context for resolving grouping keys */
interface KeyResolverContext {
  uaFamily: string;
  originalUA: string | null;
  network: Record<string, unknown>;
  device: Record<string, unknown>;
}

/** Resolver function type */
type KeyResolver = (ctx: KeyResolverContext) => string | null;

/** Built-in key resolvers */
const KEY_RESOLVERS: Record<string, KeyResolver> = {
  uaFamily: (ctx) => ctx.uaFamily,
  userAgent: (ctx) => ctx.originalUA,
  asn: (ctx) => {
    const asn = getByPath<string | number>(ctx.network, "tlsFingerprint.asn");
    return asn ? `AS${asn}` : null;
  },
  country: (ctx) =>
    getByPath<string>(ctx.network, "tlsFingerprint.country") || null,
  platform: (ctx) =>
    getByPath<string>(ctx.device, "navigator.platform") || null,
  gpu: (ctx) =>
    getByPath<string>(ctx.device, "canvasWebgl.gpu.compressedGPU") || null,
  cpuCores: (ctx) => {
    const cores = getByPath<number>(
      ctx.device,
      "workerScope.hardwareConcurrency",
    );
    return cores ? String(cores) : null;
  },
  deviceMemory: (ctx) => {
    const mem = getByPath<number>(ctx.device, "workerScope.deviceMemory");
    return mem ? String(mem) : null;
  },
  screen: (ctx) => {
    const w = getByPath<number>(ctx.device, "screen.width");
    const h = getByPath<number>(ctx.device, "screen.height");
    return w && h ? `${w}x${h}` : null;
  },
};

/**
 * Resolve a single grouping key component (built-in name or path).
 */
function resolveSingleKey(key: string, ctx: KeyResolverContext): string | null {
  // Check for built-in resolver
  const resolver = KEY_RESOLVERS[key];
  if (resolver) {
    return resolver(ctx);
  }

  // Treat as a path - try network first, then device
  const fromNetwork = getByPath<string | number>(ctx.network, key);
  if (fromNetwork !== undefined && fromNetwork !== null) {
    return String(fromNetwork);
  }

  const fromDevice = getByPath<string | number>(ctx.device, key);
  if (fromDevice !== undefined && fromDevice !== null) {
    return String(fromDevice);
  }

  return null;
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
/**
 * Resolve the grouping key for a fingerprint type based on its strategy.
 */
function resolveGroupingKey(
  strategy: GroupingStrategy,
  ctx: KeyResolverContext,
): string | null {
  // Handle composite keys (array of keys/paths)
  if (Array.isArray(strategy)) {
    const parts = strategy
      .map((key) => resolveSingleKey(key, ctx))
      .filter((v): v is string => v !== null);
    return parts.length > 0 ? parts.join(":") : null;
  }

  // Handle single key (built-in name or path)
  return resolveSingleKey(strategy, ctx);
}

// ============================================================================
// Context Fetching
// ============================================================================

/** Sources for fingerprint extraction */
interface ExtractionSources {
  network?: RawNetworkData;
  device?: Record<string, unknown>;
  hashes?: Record<string, string | undefined>;
}

/**
 * Extract all configured fingerprints from available sources.
 *
 * Each fingerprint definition specifies its source:
 * - "network": sigint/network data (default)
 * - "device": device fingerprint data
 * - "hashes": pre-computed hash values
 *
 * @param sources - Available data sources for extraction
 * @returns Map of fingerprint type to extracted value (or null if not present)
 */
function extractFingerprints(
  sources: ExtractionSources,
): Record<string, string | null> {
  const result: Record<string, string | null> = {};

  for (const [type, definition] of Object.entries(FINGERPRINT_DEFINITIONS)) {
    const source = definition.source || "network";
    let value: string | null = null;

    if (source === "hashes" && sources.hashes) {
      // Direct key lookup for hashes
      value = sources.hashes[definition.path] || null;
    } else if (source === "device" && sources.device) {
      value = getByPath<string>(sources.device, definition.path) || null;
    } else if (source === "network" && sources.network) {
      value =
        getByPath<string>(
          sources.network as Record<string, unknown>,
          definition.path,
        ) || null;
    }

    result[type] = value;
  }

  return result;
}

/** Statistical data from Valkey */
interface StatData {
  count: number;
  total: number;
  globalCount: number;
  globalTotal: number;
}

/**
 * Resolve grouping keys for all fingerprint types.
 */
function resolveAllGroupingKeys(
  types: string[],
  keyCtx: KeyResolverContext,
): Record<string, string> {
  const groupingKeys: Record<string, string> = {};
  for (const type of types) {
    const strategy = getGroupingStrategy(type);
    const key = resolveGroupingKey(strategy, keyCtx);
    groupingKeys[type] = key || keyCtx.uaFamily;
  }
  return groupingKeys;
}

/**
 * Log summary of context fetching results.
 */
function logContextSummary(
  uaFamily: string,
  scores: Record<string, FingerprintScore | null>,
  combinedScore: number | null,
  skipBaseline: boolean,
): void {
  const summary: Record<string, string | undefined> = {};
  for (const [type, score] of Object.entries(scores)) {
    if (score) {
      summary[type] = score.score.toFixed(3);
      summary[`${type}Confidence`] = score.confidence.toFixed(3);
    }
  }
  logger.info("Statistical v2 context fetched", {
    uaFamily,
    ...summary,
    combinedScore: combinedScore?.toFixed(3),
    baselineSkipped: skipBaseline,
  });
}

/**
 * Compute scores for all fingerprint types from fetched data.
 */
function computeScores(
  types: string[],
  dataResults: (StatData | null)[],
  fingerprints: Record<string, string | null>,
  groupingKeys: Record<string, string>,
): Record<string, FingerprintScore | null> {
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

    const blended = computeBlendedScore({
      uaCount: data.count,
      uaTotal: data.total,
      globalCount: data.globalCount,
      globalTotal: data.globalTotal,
      definition,
    });

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

    metrics.addMetric(
      `StatisticalV2${capitalize(type)}Score`,
      MetricUnit.NoUnit,
      blended.score,
    );
  }

  return scores;
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
/** Extract and validate user agent, returning null if invalid */
function extractUserAgent(
  fingerprint: Fingerprint,
  network: RawNetworkData | undefined,
): string | null {
  const ua = fingerprint.user_agent || network?.tcpProbe?.user_agent || null;
  if (!ua) logger.warn("Statistical v2 skipped - no user agent");
  return ua;
}

/** Input for processing fingerprints */
interface ProcessInput {
  fingerprint: Fingerprint;
  device: Record<string, Record<string, unknown> | undefined> | undefined;
  userAgent: string;
  uaFamily: string;
  fingerprints: Record<string, string | null>;
  types: string[];
  groupingKeys: Record<string, string>;
}

/** Process fingerprints and return context */
async function processFingerprints(
  input: ProcessInput,
): Promise<StatisticalContextV2> {
  const {
    fingerprint,
    device,
    userAgent,
    uaFamily,
    fingerprints,
    types,
    groupingKeys,
  } = input;

  const ruleResult = evaluateBaselineRules(
    buildRuleContext(fingerprint, device),
  );
  const skipBaseline = ruleResult.shouldSkipBaseline;
  if (skipBaseline) {
    logger.info("Skipping baseline update", {
      uaFamily,
      matchedRules: ruleResult.matchedRules,
    });
    metrics.addMetric("BaselineSkipped", MetricUnit.Count, 1);
  }

  const fetcher = skipBaseline ? fetchStatisticalV2Data : recordFingerprintV2;
  const dataPromises = types.map((type) =>
    fingerprints[type]
      ? fetcher(groupingKeys[type], type, fingerprints[type]!)
      : Promise.resolve(null),
  );

  const dataResults = await Promise.all(dataPromises);
  const scores = computeScores(types, dataResults, fingerprints, groupingKeys);
  const combinedScore = computeCombinedScore(
    Object.values(scores),
    COMBINED_MIN_CONFIDENCE,
  );

  logContextSummary(uaFamily, scores, combinedScore, skipBaseline);

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
}

/**
 * Fetch statistical v2 context for anomaly detection.
 *
 * @param fingerprint - Extracted fingerprint data
 * @param network - Raw sigint/network data
 * @param device - Raw device fingerprint data
 * @param hashes - Pre-computed hashes (maths, etc.)
 */
export async function fetchStatisticalContextV2(
  fingerprint: Fingerprint,
  network: RawNetworkData | undefined,
  device?: Record<string, Record<string, unknown> | undefined>,
  hashes?: Record<string, string | undefined>,
): Promise<StatisticalContextV2 | null> {
  if (!isStatisticalV2Enabled()) return null;

  const userAgent = extractUserAgent(fingerprint, network);
  if (!userAgent) return null;

  const uaFamily = parseUAFamily(userAgent).baselineKey;
  const fingerprints = extractFingerprints({
    network,
    device: device as Record<string, unknown>,
    hashes,
  });

  if (!Object.values(fingerprints).some((v) => v !== null)) {
    logger.debug("Statistical v2 skipped - no fingerprints available");
    return null;
  }

  const types = getFingerprintTypes();
  const keyCtx: KeyResolverContext = {
    uaFamily,
    originalUA: userAgent,
    network: network as Record<string, unknown>,
    device: device as Record<string, unknown>,
  };

  try {
    return await processFingerprints({
      fingerprint,
      device,
      userAgent,
      uaFamily,
      fingerprints,
      types,
      groupingKeys: resolveAllGroupingKeys(types, keyCtx),
    });
  } catch (error) {
    logger.warn("Statistical v2 context fetch failed", { error, uaFamily });
    metrics.addMetric("StatisticalV2ContextError", MetricUnit.Count, 1);
    return null;
  }
}

// ============================================================================
// Detection Helpers
// ============================================================================

/**
 * Check a single fingerprint for anomaly based on its thresholds.
 */
function checkFingerprintAnomaly(
  type: string,
  score: FingerprintScore,
  uaFamily: string,
): AnomalySignal | null {
  const definition = FINGERPRINT_DEFINITIONS[type];
  if (!definition) return null;

  const isAnomaly =
    score.score >= definition.anomalyThreshold &&
    score.confidence >= definition.confidenceThreshold;

  if (!isAnomaly) return null;

  logger.info(`Rare ${type.toUpperCase()} for UA detected`, {
    uaFamily,
    score: score.score.toFixed(3),
    threshold: definition.anomalyThreshold,
    confidence: score.confidence.toFixed(3),
    uaCount: score.uaCount,
    uaTotal: score.uaTotal,
  });

  metrics.addMetric(
    `StatisticalV2${capitalize(type)}Anomaly`,
    MetricUnit.Count,
    1,
  );

  const anomalyCode = definition.anomalyCode as AnomalyCode;
  if (!(anomalyCode in AnomalyCodes)) {
    logger.error(`Unknown anomaly code: ${anomalyCode}`);
    return null;
  }

  return createSignal("STATISTICAL", anomalyCode, score.score, {
    expected: `${definition.fieldName} typical for '${uaFamily}' (threshold=${definition.anomalyThreshold})`,
    actual: `score=${score.score.toFixed(3)}, seen=${score.uaCount}/${score.uaTotal}`,
    fields: [definition.fieldName, "user_agent"],
  });
}

/**
 * Build score summary string for logging.
 */
function buildScoreSummary(
  scores: Record<string, FingerprintScore | null>,
): string {
  return Object.entries(scores)
    .filter(([, s]) => s !== null)
    .map(([type, s]) => `${type}=${s?.score.toFixed(3)}`)
    .join(", ");
}

// ============================================================================
// Detection
// ============================================================================

/**
 * Detect statistical anomalies from pre-fetched v2 context.
 */
export function detectStatisticalAnomaliesV2(
  context: StatisticalContextV2 | null,
): AnomalySignal[] {
  if (!context) return [];

  const signals: AnomalySignal[] = [];
  const { uaFamily, scores, combinedScore } = context;

  // Check each fingerprint type
  for (const [type, score] of Object.entries(scores)) {
    if (!score) continue;
    const signal = checkFingerprintAnomaly(type, score, uaFamily);
    if (signal) signals.push(signal);
  }

  // Check combined score only if no individual signals
  if (
    combinedScore !== null &&
    combinedScore >= COMBINED_THRESHOLD &&
    signals.length === 0
  ) {
    const scoreSummary = buildScoreSummary(scores);

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
