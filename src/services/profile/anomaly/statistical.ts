/**
 * Statistical anomaly detection using Valkey.
 *
 * Tracks ua_family::ja4 combo frequencies to identify suspicious requests
 * where a fingerprint combination appears rarely relative to expected distribution.
 *
 * Formula:
 *   expected = total / distinct
 *   score = combo_count / expected
 *   if score < threshold AND distinct >= minDistinct: SUSPICIOUS
 *
 * @module services/profile/anomaly/statistical
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { Fingerprint } from "../../../types";
import {
  recordAndGetStats,
  isValkeyEnabled,
  type StatisticalData,
} from "../../cache";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

const logger = new Logger({
  serviceName:
    process.env.POWERTOOLS_SERVICE_NAME || "argus-statistical-detector",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/**
 * Statistical context for anomaly detection.
 * Pre-fetched from Valkey before sync detection.
 */
export interface StatisticalContext {
  /** Browser family extracted from User-Agent */
  uaFamily: string;
  /** JA4 TLS fingerprint */
  ja4: string;
  /** Statistical data from Valkey */
  stats: StatisticalData;
  /** Computed score (combo_count / expected) */
  score: number;
}

/**
 * Fetch statistical context for anomaly detection.
 *
 * This async function should be called early in the request pipeline
 * to pre-fetch data from Valkey. The returned context is then passed
 * to the sync detectStatisticalAnomalies function.
 *
 * @param fingerprint - Fingerprint data containing user_agent and ja4
 * @returns Statistical context or null if detection is disabled/not applicable
 *
 * @example
 * ```typescript
 * // Pre-fetch context (async)
 * const ctx = await fetchStatisticalContext(fingerprint);
 *
 * // Later, detect anomalies (sync)
 * const signals = detectStatisticalAnomalies(ctx);
 * ```
 */
export async function fetchStatisticalContext(
  fingerprint: Fingerprint,
): Promise<StatisticalContext | null> {
  // Check if statistical detection is enabled
  if (!isValkeyEnabled()) {
    return null;
  }

  // Need both user_agent and ja4 for statistical detection
  const { user_agent, ja4 } = fingerprint;
  if (!user_agent || !ja4) {
    return null;
  }

  // Use full user-agent string for grouping (matches ja4db approach)
  const uaFamily = user_agent;
  const stats = await recordAndGetStats(uaFamily, ja4);

  // Compute score: combo_count / expected
  // expected = total / distinct
  const expected = stats.total / stats.distinct;
  const score = stats.comboCount / expected;

  // Emit metrics for monitoring
  metrics.addMetric("StatisticalScore", MetricUnit.NoUnit, score);
  metrics.addMetric("StatisticalDistinct", MetricUnit.Count, stats.distinct);

  logger.debug("Statistical context fetched", {
    uaFamily,
    ja4: ja4.substring(0, 20) + "...",
    total: stats.total,
    comboCount: stats.comboCount,
    distinct: stats.distinct,
    expected,
    score,
  });

  return {
    uaFamily,
    ja4,
    stats,
    score,
  };
}

/**
 * Detect statistical anomalies from pre-fetched context.
 *
 * This sync function uses the context returned by fetchStatisticalContext
 * to determine if the fingerprint combination is statistically suspicious.
 *
 * Detection logic:
 * 1. Skip if distinct < threshold (not enough data for statistical significance)
 * 2. Flag as suspicious if score < threshold (combo appears too rarely)
 * 3. Severity scales inversely with score (lower score = higher severity)
 *
 * @param context - Pre-fetched statistical context, or null to skip detection
 * @returns Array of anomaly signals (empty if no anomalies detected)
 */
export function detectStatisticalAnomalies(
  context: StatisticalContext | null,
): AnomalySignal[] {
  if (!context) {
    return [];
  }

  const { uaFamily, ja4, stats, score } = context;

  // Get thresholds from environment (with defaults)
  const scoreThreshold = parseFloat(
    process.env.STATISTICAL_SCORE_THRESHOLD || "0.01",
  );
  const distinctThreshold = parseInt(
    process.env.STATISTICAL_DISTINCT_THRESHOLD || "50",
    10,
  );

  // Skip detection if not enough distinct values for statistical significance
  if (stats.distinct < distinctThreshold) {
    logger.debug("Statistical detection skipped - insufficient data", {
      distinct: stats.distinct,
      threshold: distinctThreshold,
    });
    return [];
  }

  // Check if combo is suspiciously rare
  if (score < scoreThreshold) {
    // Severity scales inversely with score
    // score=0.01 → severity=0.5, score=0.001 → severity=0.75, score=0.0001 → severity=0.9
    // Formula: severity = 0.5 + 0.4 * (1 - score / scoreThreshold)
    const severity = Math.min(0.9, 0.5 + 0.4 * (1 - score / scoreThreshold));

    logger.info("Rare fingerprint combo detected", {
      uaFamily,
      ja4: ja4.substring(0, 30) + "...",
      score,
      severity,
      stats,
    });

    metrics.addMetric("RareFingerprintComboDetected", MetricUnit.Count, 1);

    return [
      createSignal(
        "STATISTICAL",
        AnomalyCodes.RARE_FINGERPRINT_COMBO,
        severity,
        {
          expected: `UA family '${uaFamily}' should have score >= ${scoreThreshold}`,
          actual: `score=${score.toFixed(6)} (combo=${stats.comboCount}, expected=${(stats.total / stats.distinct).toFixed(1)})`,
          fields: ["user_agent", "ja4"],
        },
      ),
    ];
  }

  return [];
}
