/**
 * Cross-field anomaly detection.
 *
 * Detects inconsistencies between Navigator and Worker scope properties.
 * Spoofed browsers often modify navigator values but forget to patch
 * the corresponding values in Worker scopes.
 * @module
 */
import { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";

const FIELDS: { key: string; severity: number }[] = [
  { key: "userAgent", severity: 0.8 },
  { key: "platform", severity: 0.75 },
  { key: "hardwareConcurrency", severity: 0.7 },
];

const DISPLAY: Record<string, string> = {
  navigator: "Navigator (main)",
  workerScope: "Worker",
  dedicatedWorker: "Dedicated Worker",
  sharedWorker: "Shared Worker",
  serviceWorker: "Service Worker",
};

const WORKER_KEYS: [string, string][] = [
  ["web", "dedicatedWorker"],
  ["shared", "sharedWorker"],
  ["service", "serviceWorker"],
];

type Env = [string, Record<string, unknown>];

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function truncate(v: unknown, max = 50): string {
  if (v == null) return "(undefined)";
  const s = String(v);
  return s.length <= max ? s : s.substring(0, max - 3) + "...";
}

/** Extract named worker scopes from the nested scopes object. */
function extractWorkerScopes(scopes: Record<string, unknown>): Env[] {
  const envs: Env[] = [];
  for (const [k, name] of WORKER_KEYS) {
    const s = scopes[k];
    if (isObj(s)) envs.push([name, s]);
  }
  return envs;
}

/** Collect navigator + worker scopes from the device payload. */
function collectScopes(device: Record<string, unknown>): Env[] {
  const envs: Env[] = [];
  if (isObj(device.navigator)) envs.push(["navigator", device.navigator]);

  const ws = device.workerScope;
  if (!isObj(ws)) return envs;

  if (isObj(ws.scopes)) return [...envs, ...extractWorkerScopes(ws.scopes)];

  // Legacy fallback: top-level workerScope without nested scopes
  if (
    envs.length === 1 &&
    (ws.userAgent || ws.platform || ws.hardwareConcurrency)
  )
    envs.push(["workerScope", ws]);

  return envs;
}

/** Compare two scopes and return signals for any field mismatches. */
function compareScopes([n1, e1]: Env, [n2, e2]: Env): AnomalySignal[] {
  const signals: AnomalySignal[] = [];
  for (const { key, severity } of FIELDS) {
    const v1 = e1[key],
      v2 = e2[key];
    if (v1 !== undefined && v2 !== undefined && v1 !== v2) {
      signals.push(
        createSignal("CROSS_FIELD", AnomalyCodes.WORKER_MISMATCH, severity, {
          expected: `${DISPLAY[n1]} ${key} matches ${DISPLAY[n2]}`,
          actual: `${DISPLAY[n1]}: ${truncate(v1)} vs ${DISPLAY[n2]}: ${truncate(v2)}`,
          fields: [`${n1}.${key}`, `${n2}.${key}`],
        }),
      );
    }
  }
  return signals;
}

/** Detect inconsistencies between Navigator and Worker scope properties. */
export function detectCrossFieldAnomalies(
  _fingerprint: Fingerprint,
  raw?: unknown,
): AnomalySignal[] {
  if (!isObj(raw)) return [];
  const envs = collectScopes(raw);

  const signals: AnomalySignal[] = [];
  for (let i = 0; i < envs.length; i++) {
    for (let j = i + 1; j < envs.length; j++) {
      signals.push(...compareScopes(envs[i], envs[j]));
    }
  }
  return signals;
}
