// src/services/profile/anomaly/cross-field.ts
// AR-145: Cross-field anomaly detection (Navigator vs Worker mismatch)

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Raw fingerprint payload structure (nested web library format)
 * Only the fields we need for cross-field detection
 */
interface RawLoosePayload {
  loose?: {
    navigator?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
      [key: string]: unknown;
    };
    workerScope?: {
      userAgent?: string;
      platform?: string;
      hardwareConcurrency?: number;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Truncate string for evidence display
 * Shows first N chars with ellipsis if truncated
 */
function truncate(str: string | undefined, maxLen: number = 50): string {
  if (!str) return "(undefined)";
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}

/**
 * Detect cross-field anomalies between Navigator and Worker scope
 *
 * Spoofed browsers often modify navigator values but forget to modify
 * the corresponding values in the Worker scope, creating detectable mismatches.
 *
 * @param fingerprint - Normalized fingerprint (not used directly, but matches detector signature)
 * @param raw - Raw fingerprint payload with loose.navigator and loose.workerScope
 * @returns Array of anomaly signals for detected mismatches
 */
export function detectCrossFieldAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  // Return empty if no raw payload
  if (!raw || typeof raw !== "object") {
    return signals;
  }

  const payload = raw as RawLoosePayload;

  // Check for loose data structure
  if (!payload.loose || typeof payload.loose !== "object") {
    return signals;
  }

  const navigator = payload.loose.navigator;
  const workerScope = payload.loose.workerScope;

  // If either navigator or workerScope is missing, can't compare
  if (!navigator || !workerScope) {
    return signals;
  }

  // Check userAgent mismatch
  if (
    navigator.userAgent !== undefined &&
    workerScope.userAgent !== undefined &&
    navigator.userAgent !== workerScope.userAgent
  ) {
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.WORKER_MISMATCH,
        0.8,
        `Navigator UA matches Worker UA`,
        `Navigator: ${truncate(navigator.userAgent)} vs Worker: ${truncate(workerScope.userAgent)}`,
        ["navigator.userAgent", "workerScope.userAgent"],
      ),
    );
  }

  // Check platform mismatch
  if (
    navigator.platform !== undefined &&
    workerScope.platform !== undefined &&
    navigator.platform !== workerScope.platform
  ) {
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.WORKER_MISMATCH,
        0.75,
        `Navigator platform matches Worker platform`,
        `Navigator: ${navigator.platform} vs Worker: ${workerScope.platform}`,
        ["navigator.platform", "workerScope.platform"],
      ),
    );
  }

  // Check hardwareConcurrency mismatch
  if (
    navigator.hardwareConcurrency !== undefined &&
    workerScope.hardwareConcurrency !== undefined &&
    navigator.hardwareConcurrency !== workerScope.hardwareConcurrency
  ) {
    signals.push(
      createSignal(
        "CROSS_FIELD",
        AnomalyCodes.WORKER_MISMATCH,
        0.7,
        `Navigator hardwareConcurrency matches Worker`,
        `Navigator: ${navigator.hardwareConcurrency} vs Worker: ${workerScope.hardwareConcurrency}`,
        ["navigator.hardwareConcurrency", "workerScope.hardwareConcurrency"],
      ),
    );
  }

  return signals;
}
