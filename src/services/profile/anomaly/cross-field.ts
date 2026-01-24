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
 * Worker scope structure from web library
 * Contains scopes for different worker types
 */
interface WorkerScopeData extends EnvironmentScope {
  scopes?: {
    main?: EnvironmentScope;
    web?: EnvironmentScope;
    shared?: EnvironmentScope | null;
    service?: EnvironmentScope | string;
  };
}

/**
 * Device payload structure (V3 format from ms-argus-web)
 * The device section is passed directly from matching-worker (rawPayload.device)
 * Structure:
 * - navigator: main thread navigator
 * - workerScope.scopes.web: dedicated worker
 * - workerScope.scopes.shared: shared worker (null if unavailable)
 * - workerScope.scopes.service: service worker ("unavailable" if blocked)
 */
interface DevicePayload {
  navigator?: EnvironmentScope;
  workerScope?: WorkerScopeData;
  [key: string]: unknown;
}

type EnvironmentName =
  | "navigator"
  | "workerScope"
  | "dedicatedWorker"
  | "sharedWorker"
  | "serviceWorker";

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

function truncate(value: unknown, maxLen: number = 50): string {
  if (value === undefined || value === null) return "(undefined)";
  const str = String(value);
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}

/**
 * Extract all available environment scopes from device payload
 * Reads from the V3 device structure:
 * - navigator (main thread)
 * - workerScope.scopes.web (dedicated worker)
 * - workerScope.scopes.shared (shared worker, null if unavailable)
 * - workerScope.scopes.service (service worker, "unavailable" if blocked)
 */
function isObjectScope(val: unknown): val is EnvironmentScope {
  return val !== null && typeof val === "object";
}

function hasComparableFields(ws: EnvironmentScope): boolean {
  return (
    !ws.scopes && !!(ws.userAgent || ws.platform || ws.hardwareConcurrency)
  );
}

function extractWorkerScopes(
  device: DevicePayload,
  environments: Map<EnvironmentName, EnvironmentScope>,
): void {
  const scopes = device.workerScope?.scopes;
  if (scopes) {
    if (isObjectScope(scopes.web))
      environments.set("dedicatedWorker", scopes.web);
    if (isObjectScope(scopes.shared))
      environments.set("sharedWorker", scopes.shared);
    if (isObjectScope(scopes.service))
      environments.set("serviceWorker", scopes.service);
    return;
  }

  const ws = device.workerScope;
  if (environments.size === 1 && isObjectScope(ws) && hasComparableFields(ws)) {
    environments.set("workerScope", ws);
  }
}

function extractEnvironments(
  device: DevicePayload,
): Map<EnvironmentName, EnvironmentScope> {
  const environments = new Map<EnvironmentName, EnvironmentScope>();

  if (isObjectScope(device.navigator)) {
    environments.set("navigator", device.navigator);
  }

  extractWorkerScopes(device, environments);
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

    if (val1 !== undefined && val2 !== undefined && val1 !== val2) {
      const env1Display = ENV_DISPLAY_NAMES[env1Name];
      const env2Display = ENV_DISPLAY_NAMES[env2Name];

      signals.push(
        createSignal("CROSS_FIELD", AnomalyCodes.WORKER_MISMATCH, severity, {
          expected: `${env1Display} ${displayName} matches ${env2Display}`,
          actual: `${env1Display}: ${truncate(val1)} vs ${env2Display}: ${truncate(val2)}`,
          fields: [`${env1Name}.${field}`, `${env2Name}.${field}`],
        }),
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
 * - Dedicated Workers (workerScope.scopes.web)
 * - Shared Workers (workerScope.scopes.shared)
 * - Service Workers (workerScope.scopes.service)
 * - Generic workerScope (legacy/fallback for older payloads)
 *
 * @param fingerprint - Normalized fingerprint (not used directly, but matches detector signature)
 * @param raw - Device payload from V3 format (rawPayload.device from matching-worker)
 * @returns Array of anomaly signals for detected mismatches
 */
export function detectCrossFieldAnomalies(
  fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  if (!raw || typeof raw !== "object") {
    return signals;
  }

  const device = raw as DevicePayload;

  const environments = extractEnvironments(device);

  if (environments.size < 2) {
    return signals;
  }

  const envNames = Array.from(environments.keys());
  const seenPairs = new Set<string>();

  for (let i = 0; i < envNames.length; i++) {
    for (let j = i + 1; j < envNames.length; j++) {
      const env1Name = envNames[i];
      const env2Name = envNames[j];

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
