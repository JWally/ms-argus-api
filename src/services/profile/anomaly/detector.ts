// src/services/profile/anomaly/detector.ts
// AR-141: Simple detector orchestrator - no registry class, just an array of functions

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyResult } from "./types";
import { detectQuickWinAnomalies } from "./quick-wins";
import { detectCrossFieldAnomalies } from "./cross-field";
import { detectBrowserEngineAnomalies } from "./browser-engine";
import { detectNetworkAnomalies } from "./network";

/**
 * Sigint data structure for network anomaly detection
 */
interface SigintData {
  geo?: {
    lat?: number;
    lon?: number;
    timezone?: string;
  };
  tcpProbe?: {
    rttMs?: number;
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
  // Phase 3: Browser engine anomalies (AR-143)
  detectBrowserEngineAnomalies,
  // Phase 4: Network anomalies (AR-144)
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
