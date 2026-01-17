// src/services/profile/anomaly/detector.ts
// AR-141: Simple detector orchestrator - no registry class, just an array of functions

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyResult } from "./types";

/**
 * Detector function signature
 * Takes fingerprint and optional raw payload, returns array of signals
 */
type DetectorFn = (fingerprint: Fingerprint, raw?: unknown) => AnomalySignal[];

/**
 * Array of detector functions - add more as phases complete
 * Each detector is isolated with try/catch for error resilience
 */
const detectors: DetectorFn[] = [
  // Phase 1: detectQuickWinAnomalies will be added here
  // Phase 2: detectCrossFieldAnomalies will be added here
  // Phase 3: detectBrowserEngineAnomalies will be added here
  // Phase 4: detectNetworkAnomalies will be added here
];

/**
 * Run all registered anomaly detectors
 * Errors in individual detectors are caught and logged, not propagated
 */
export function detectAllAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalyResult {
  const signals: AnomalySignal[] = [];

  for (const detector of detectors) {
    try {
      signals.push(...detector(fingerprint, raw));
    } catch (error) {
      // Log but don't fail - detector errors shouldn't block matching
      console.error("Anomaly detector failed:", error);
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
export function registerDetector(detector: DetectorFn): void {
  detectors.push(detector);
}

/**
 * Get count of registered detectors (for testing)
 */
export function getDetectorCount(): number {
  return detectors.length;
}
