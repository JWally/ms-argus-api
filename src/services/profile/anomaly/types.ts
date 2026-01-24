// src/services/profile/anomaly/types.ts
// AR-141: Anomaly detection types - minimal structure for Phase 1

/**
 * Type of anomaly detected
 */
export type AnomalyType = "CROSS_FIELD" | "NETWORK" | "HARDWARE" | "IDENTITY";

/**
 * Anomaly codes as const object for type-safe lookup
 * Uses const assertions to catch typos at compile time
 */
export const AnomalyCodes = {
  // Cross-field anomalies
  NAVIGATOR_LIES: "NAVIGATOR_LIES",
  WORKER_MISMATCH: "WORKER_MISMATCH",
  SCREEN_CSS_MISMATCH: "SCREEN_CSS_MISMATCH",
  // Network anomalies
  IP_TIMEZONE_MISMATCH: "IP_TIMEZONE_MISMATCH",
  SERVER_CLIENT_TZ_MISMATCH: "SERVER_CLIENT_TZ_MISMATCH",
  JA4_UA_MISMATCH: "JA4_UA_MISMATCH",
  // Quick win anomalies
  HEADLESS_DETECTED: "HEADLESS_DETECTED",
  HIGH_PROXY_SCORE: "HIGH_PROXY_SCORE",
  HIGH_VPN_SCORE: "HIGH_VPN_SCORE",
} as const;

export type AnomalyCode = (typeof AnomalyCodes)[keyof typeof AnomalyCodes];

/**
 * Evidence structure for anomaly signals
 */
export interface AnomalyEvidence {
  expected: string;
  actual: string;
  fields?: string[];
}

/**
 * Individual anomaly signal
 */
export interface AnomalySignal {
  type: AnomalyType;
  code: AnomalyCode;
  severity: number; // 0-1, runtime clamped
  evidence: AnomalyEvidence;
}

/**
 * Aggregated result from all anomaly detectors
 */
export interface AnomalyResult {
  signals: AnomalySignal[];
  aggregateScore: number;
  suggestedFlags: string[];
}

/**
 * Helper to create signals with clamped severity
 */
export function createSignal(
  type: AnomalyType,
  code: AnomalyCode,
  severity: number,
  evidence: AnomalyEvidence,
): AnomalySignal {
  return {
    type,
    code,
    severity: Math.max(0, Math.min(1, severity)),
    evidence,
  };
}
