/**
 * Worker scope divergence analysis for integrity ingestion.
 *
 * Compares main-thread, dedicated worker, and shared worker scopes
 * to detect spoofing that only patches the main thread.
 */

import { detectCrossFieldAnomalies } from "../../services/profile/anomaly/worker-scope-consistency";
import type { Fingerprint } from "../../types";

const COMPARE_FIELDS = [
  "userAgent",
  "platform",
  "hardwareConcurrency",
  "deviceMemory",
  "languages",
  "webglRenderer",
  "webglVendor",
  "webgl2Renderer",
  "webgl2Vendor",
  "appVersion",
  "product",
  "onLine",
] as const;

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

interface Divergence {
  field: string;
  main: unknown;
  web: unknown;
  shared: unknown;
}

export interface WorkerAnalysisResult {
  lied: boolean;
  divergences: Divergence[];
  signals: Array<{ code: string; severity: number; evidence: string }>;
}

const EMPTY: WorkerAnalysisResult = {
  lied: false,
  divergences: [],
  signals: [],
};

function resolveMainScope(
  scopes: Record<string, unknown> | null,
  device: Record<string, unknown>,
): Record<string, unknown> | null {
  if (scopes && isObj(scopes.main)) return scopes.main;
  if (isObj(device.navigator)) return device.navigator;
  return null;
}

function getScope(
  scopes: Record<string, unknown> | null,
  key: string,
): Record<string, unknown> | null {
  if (!scopes) return null;
  const s = scopes[key];
  return isObj(s) ? s : null;
}

function pairsDiverge(values: (unknown | undefined)[]): boolean {
  const defined = values.filter((v) => v !== undefined);
  return defined.length >= 2 && !defined.every((v) => v === defined[0]);
}

function findDivergences(
  mainScope: Record<string, unknown> | null,
  webScope: Record<string, unknown> | null,
  sharedScope: Record<string, unknown> | null,
): Divergence[] {
  const result: Divergence[] = [];
  for (const field of COMPARE_FIELDS) {
    const m = mainScope?.[field];
    const w = webScope?.[field];
    const s = sharedScope?.[field];
    if (pairsDiverge([m, w, s])) {
      result.push({ field, main: m, web: w, shared: s });
    }
  }
  return result;
}

function formatSignals(
  signals: ReturnType<typeof detectCrossFieldAnomalies>,
): WorkerAnalysisResult["signals"] {
  return signals.map((s) => ({
    code: s.code,
    severity: s.severity,
    evidence: s.evidence.actual,
  }));
}

/**
 * Analyze worker scope divergences in the integrity payload.
 *
 * @param device - The device object from the integrity payload
 */
export function analyzeWorkerScopes(device: unknown): WorkerAnalysisResult {
  if (!isObj(device)) return EMPTY;

  const anomalySignals = detectCrossFieldAnomalies({} as Fingerprint, device);

  const ws = device.workerScope;
  if (!isObj(ws)) {
    return anomalySignals.length > 0
      ? { lied: true, divergences: [], signals: formatSignals(anomalySignals) }
      : EMPTY;
  }

  const scopes = isObj(ws.scopes) ? ws.scopes : null;
  const mainScope = resolveMainScope(scopes, device);
  const divergences = findDivergences(
    mainScope,
    getScope(scopes, "web"),
    getScope(scopes, "shared"),
  );

  const lied = anomalySignals.length > 0 || divergences.length > 0;
  return { lied, divergences, signals: formatSignals(anomalySignals) };
}
