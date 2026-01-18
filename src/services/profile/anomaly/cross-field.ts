// src/services/profile/anomaly/cross-field.ts
// AR-145: Cross-field anomaly detection (Navigator vs Worker scope mismatches)
// Extended to support multiple worker environments (dedicated, shared, service)

import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

/**
 * Environment scope with comparable fields
 */
interface EnvironmentScope {
  userAgent?: string;
  platform?: string;
  hardwareConcurrency?: number;
  [key: string]: unknown;
}

/**
 * Raw fingerprint payload structure (nested web library format)
 * Supports multiple worker environment types
 */
interface RawLoosePayload {
  loose?: {
    navigator?: EnvironmentScope;
    workerScope?: EnvironmentScope; // Generic/legacy worker scope
    dedicatedWorker?: EnvironmentScope;
    sharedWorker?: EnvironmentScope;
    serviceWorker?: EnvironmentScope;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Environment names for display
 */
type EnvironmentName =
  | "navigator"
  | "workerScope"
  | "dedicatedWorker"
  | "sharedWorker"
  | "serviceWorker";

/**
 * Human-readable environment names for evidence
 */
const ENV_DISPLAY_NAMES: Record<EnvironmentName, string> = {
  navigator: "Navigator (main)",
  workerScope: "Worker",
  dedicatedWorker: "Dedicated Worker",
  sharedWorker: "Shared Worker",
  serviceWorker: "Service Worker",
};

/**
 * Fields to compare across environments with their severity weights
 * Higher severity = more suspicious when mismatched
 */
const COMPARABLE_FIELDS: {
  field: keyof EnvironmentScope;
  severity: number;
  displayName: string;
}[] = [
  { field: "userAgent", severity: 0.8, displayName: "userAgent" },
  { field: "platform", severity: 0.75, displayName: "platform" },
  {
    field: "hardwareConcurrency",
    severity: 0.7,
    displayName: "hardwareConcurrency",
  },
];

/**
 * Truncate string for evidence display
 * Shows first N chars with ellipsis if truncated
 */
function truncate(value: unknown, maxLen: number = 50): string {
  if (value === undefined || value === null) return "(undefined)";
  const str = String(value);
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}

/**
 * Extract all available environment scopes from payload
 */
function extractEnvironments(
  loose: NonNullable<RawLoosePayload["loose"]>,
): Map<EnvironmentName, EnvironmentScope> {
  const environments = new Map<EnvironmentName, EnvironmentScope>();

  // Add each environment if present
  if (loose.navigator && typeof loose.navigator === "object") {
    environments.set("navigator", loose.navigator);
  }
  if (loose.workerScope && typeof loose.workerScope === "object") {
    environments.set("workerScope", loose.workerScope);
  }
  if (loose.dedicatedWorker && typeof loose.dedicatedWorker === "object") {
    environments.set("dedicatedWorker", loose.dedicatedWorker);
  }
  if (loose.sharedWorker && typeof loose.sharedWorker === "object") {
    environments.set("sharedWorker", loose.sharedWorker);
  }
  if (loose.serviceWorker && typeof loose.serviceWorker === "object") {
    environments.set("serviceWorker", loose.serviceWorker);
  }

  return environments;
}

/**
 * Compare two environments and return mismatches
 */
function compareEnvironments(
  env1Name: EnvironmentName,
  env1: EnvironmentScope,
  env2Name: EnvironmentName,
  env2: EnvironmentScope,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  for (const { field, severity, displayName } of COMPARABLE_FIELDS) {
    const val1 = env1[field];
    const val2 = env2[field];

    // Only compare if both environments have the field
    if (val1 !== undefined && val2 !== undefined && val1 !== val2) {
      const env1Display = ENV_DISPLAY_NAMES[env1Name];
      const env2Display = ENV_DISPLAY_NAMES[env2Name];

      signals.push(
        createSignal(
          "CROSS_FIELD",
          AnomalyCodes.WORKER_MISMATCH,
          severity,
          `${env1Display} ${displayName} matches ${env2Display}`,
          `${env1Display}: ${truncate(val1)} vs ${env2Display}: ${truncate(val2)}`,
          [`${env1Name}.${field}`, `${env2Name}.${field}`],
        ),
      );
    }
  }

  return signals;
}

/**
 * Detect cross-field anomalies between Navigator and all Worker scopes
 *
 * Spoofed browsers often modify navigator values but forget to modify
 * the corresponding values in one or more Worker scopes, creating detectable mismatches.
 *
 * Checks consistency across:
 * - Navigator (main thread)
 * - Dedicated Workers (new Worker())
 * - Shared Workers (new SharedWorker())
 * - Service Workers
 * - Generic workerScope (legacy/fallback)
 *
 * @param fingerprint - Normalized fingerprint (not used directly, but matches detector signature)
 * @param raw - Raw fingerprint payload with loose.navigator and worker scopes
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

  // Extract all available environments
  const environments = extractEnvironments(payload.loose);

  // Need at least 2 environments to compare
  if (environments.size < 2) {
    return signals;
  }

  // Compare all pairs of environments
  const envNames = Array.from(environments.keys());
  const seenPairs = new Set<string>();

  for (let i = 0; i < envNames.length; i++) {
    for (let j = i + 1; j < envNames.length; j++) {
      const env1Name = envNames[i];
      const env2Name = envNames[j];

      // Create a canonical pair key to avoid duplicates
      const pairKey = [env1Name, env2Name].sort().join("|");
      if (seenPairs.has(pairKey)) continue;
      seenPairs.add(pairKey);

      const env1 = environments.get(env1Name)!;
      const env2 = environments.get(env2Name)!;

      signals.push(...compareEnvironments(env1Name, env1, env2Name, env2));
    }
  }

  return signals;
}
