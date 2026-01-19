// src/services/profile/anomaly/detector.ts
// AR-141: Simple detector orchestrator - no registry class, just an array of functions
// AR-158: Replaced console.error with Powertools structured logging and metrics

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyResult } from "./types";
import { detectQuickWinAnomalies } from "./quick-wins";
import { detectCrossFieldAnomalies } from "./cross-field";
import { detectNetworkAnomalies } from "./network";

// AR-158: Structured logging for anomaly detection
const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "argus-anomaly-detector",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/**
 * Sigint data structure for network anomaly detection
 */
interface SigintData {
  geo?: {
    timezone?: string;
  };
}

/**
 * Detector function signature
 * Takes fingerprint, optional raw payload, and optional sigint data
 */
type DetectorFn = (
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: SigintData,
) => AnomalySignal[];

/**
 * Array of detector functions - add more as phases complete
 * Each detector is isolated with try/catch for error resilience
 */
const detectors: DetectorFn[] = [
  // Phase 1: Quick wins (AR-142)
  detectQuickWinAnomalies,
  // Phase 2: Cross-field anomalies (AR-145)
  detectCrossFieldAnomalies,
  // Phase 3: Network anomalies (AR-144)
  detectNetworkAnomalies,
];

/**
 * Run all registered anomaly detectors
 * Errors in individual detectors are caught and logged, not propagated
 *
 * @param fingerprint - Normalized fingerprint data
 * @param raw - Raw payload with nested structure (for cross-field checks)
 * @param sigint - Signal intelligence data (for network checks)
 */
export function detectAllAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: SigintData,
): AnomalyResult {
  const signals: AnomalySignal[] = [];

  for (const detector of detectors) {
    try {
      signals.push(...detector(fingerprint, raw, sigint));
    } catch (error) {
      // Log but don't fail - detector errors shouldn't block matching
      // AR-158: Use structured logging and emit metric for monitoring
      logger.error("Anomaly detector failed", {
        error,
        detectorName: detector.name,
      });
      metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
    }
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
 */
function computeAggregateScore(signals: AnomalySignal[]): number {
  if (signals.length === 0) return 0;
  const total = signals.reduce((sum, s) => sum + s.severity, 0);
  return Math.min(total, 1.0);
}

/**
 * Convert anomaly code to flag name
 * Uses lowercase with underscores to match DeviceFlags pattern
 */
function codeToFlag(code: string): string {
  return code.toLowerCase();
}

/**
 * Register a new detector function
 * Used by detector modules to add themselves to the detector array
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
 */
export function getDetectorCount(): number {
  return detectors.length;
}
