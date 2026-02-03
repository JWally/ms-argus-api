/**
 * Anomaly detection orchestrator.
 *
 * Coordinates multiple anomaly detectors to identify suspicious patterns
 * in fingerprint data. Uses a registry pattern for extensibility with
 * error isolation so individual detector failures don't block matching.
 * @module
 */
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyResult } from "./types";
import { detectQuickWinAnomalies } from "./quick-wins";
import { detectCrossFieldAnomalies } from "./cross-field";
import { detectNetworkAnomalies } from "./network";
import {
  detectStatisticalAnomalies,
  type StatisticalContext,
} from "./statistical";
import {
  detectNetworkBaselineAnomalies,
  type NetworkBaselineDetectorContext,
} from "./network-baseline-detector";
import {
  detectStatisticalAnomaliesV2,
  type StatisticalContextV2,
} from "./statistical-v2";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-anomaly-detector",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/** Sigint data structure for network anomaly detection. */
interface SigintData {
  /** Geographic data from IP lookup */
  geo?: {
    /** Timezone from IP geolocation */
    timezone?: string;
  };
}

/**
 * Detector function signature.
 *
 * Takes fingerprint, optional raw payload, and optional sigint data.
 * Must return array of anomaly signals (can be empty).
 */
type DetectorFn = (
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: SigintData,
) => AnomalySignal[];

/**
 * Registered detector functions.
 *
 * Each detector is isolated with try/catch for error resilience.
 * Detectors are called in registration order.
 */
const detectors: DetectorFn[] = [
  detectQuickWinAnomalies,
  detectCrossFieldAnomalies,
  detectNetworkAnomalies,
];

/**
 * Run all registered anomaly detectors
 * Errors in individual detectors are caught and logged, not propagated
 * @param fingerprint - Normalized fingerprint data
 * @param raw - Raw payload with nested structure (for cross-field checks)
 * @param sigint - Signal intelligence data (for network checks)
 * @param statisticalContext - Pre-fetched statistical context (for statistical checks)
 * @param networkBaselineContext - Pre-fetched network baseline context (for ASN-based checks)
 * @param statisticalContextV2 - Pre-fetched statistical v2 context (Shannon scoring)
 * @returns Aggregated anomaly result with signals, score, and suggested flags
 */
export function detectAllAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: SigintData,
  statisticalContext?: StatisticalContext | null,
  networkBaselineContext?: NetworkBaselineDetectorContext | null,
  statisticalContextV2?: StatisticalContextV2 | null,
): AnomalyResult {
  const signals: AnomalySignal[] = [];

  for (const detector of detectors) {
    try {
      signals.push(...detector(fingerprint, raw, sigint));
    } catch (error) {
      // Detector errors shouldn't block matching
      logger.error("Anomaly detector failed", {
        error,
        detectorName: detector.name,
      });
      metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
    }
  }

  // Run statistical detection with pre-fetched context
  try {
    signals.push(...detectStatisticalAnomalies(statisticalContext ?? null));
  } catch (error) {
    logger.error("Statistical anomaly detector failed", { error });
    metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
  }

  // Run network baseline detection with pre-fetched context
  try {
    signals.push(
      ...detectNetworkBaselineAnomalies(networkBaselineContext ?? null),
    );
  } catch (error) {
    logger.error("Network baseline anomaly detector failed", { error });
    metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
  }

  // Run statistical v2 detection with pre-fetched context (Shannon scoring)
  try {
    signals.push(...detectStatisticalAnomaliesV2(statisticalContextV2 ?? null));
  } catch (error) {
    logger.error("Statistical v2 anomaly detector failed", { error });
    metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
  }

  return {
    signals,
    aggregateScore: computeAggregateScore(signals),
    suggestedFlags: signals.map((s) => codeToFlag(s.code)),
  };
}

/**
 * Compute aggregate anomaly score from signals
 * Sums severities and caps at 1.0
 * @param signals - Array of anomaly signals
 * @returns Aggregate score between 0.0 and 1.0
 */
function computeAggregateScore(signals: AnomalySignal[]): number {
  if (signals.length === 0) return 0;
  const total = signals.reduce((sum, s) => sum + s.severity, 0);
  return Math.min(total, 1.0);
}

/**
 * Convert anomaly code to flag name
 * Uses lowercase with underscores to match DeviceFlags pattern
 * @param code - Anomaly code (e.g., "WORKER_MISMATCH")
 * @returns Flag name (e.g., "worker_mismatch")
 */
function codeToFlag(code: string): string {
  return code.toLowerCase();
}

/**
 * Register a new detector function
 * Detectors are called in registration order
 * @param detector - Detector function that returns anomaly signals
 */
export function registerDetector(
  detector: (
    fingerprint: Fingerprint,
    raw?: unknown,
    sigint?: SigintData,
  ) => AnomalySignal[],
): void {
  detectors.push(detector);
}

/**
 * Get count of registered detectors (for testing)
 * @returns Number of registered detector functions
 */
export function getDetectorCount(): number {
  return detectors.length;
}
