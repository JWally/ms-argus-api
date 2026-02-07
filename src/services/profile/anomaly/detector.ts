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
  detectNetworkBaselineAnomalies,
  type NetworkBaselineDetectorContext,
} from "./network-baseline-detector";
import {
  detectStatisticalAnomaliesV2,
  type StatisticalContextV2,
} from "./statistical-v2";
import { detectIpHistoryAnomalies } from "./ip-history-detector";
import type { DeviceProfile } from "../../../types/profile";

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

/** Run a detector with error isolation, appending results to signals. */
function runSafe(
  signals: AnomalySignal[],
  name: string,
  fn: () => AnomalySignal[],
): void {
  try {
    signals.push(...fn());
  } catch (error) {
    logger.error(`${name} failed`, { error });
    metrics.addMetric("AnomalyDetectorError", MetricUnit.Count, 1);
  }
}

/**
 * Run all registered anomaly detectors.
 * Errors in individual detectors are caught and logged, not propagated.
 */
export function detectAllAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: SigintData,
  contextOpts?: {
    networkBaseline?: NetworkBaselineDetectorContext | null;
    statisticalV2?: StatisticalContextV2 | null;
    ipHistoryProfile?: DeviceProfile | null;
  },
): AnomalyResult {
  const signals: AnomalySignal[] = [];

  for (const detector of detectors) {
    runSafe(signals, detector.name, () => detector(fingerprint, raw, sigint));
  }

  runSafe(signals, "NetworkBaseline", () =>
    detectNetworkBaselineAnomalies(contextOpts?.networkBaseline ?? null),
  );
  runSafe(signals, "StatisticalV2", () =>
    detectStatisticalAnomaliesV2(contextOpts?.statisticalV2 ?? null),
  );
  runSafe(signals, "IpHistory", () =>
    detectIpHistoryAnomalies(
      fingerprint,
      contextOpts?.ipHistoryProfile ?? null,
    ),
  );

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
