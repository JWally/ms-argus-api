/**
 * Worker scope divergence analysis for integrity ingestion.
 *
 * Compares main-thread, dedicated worker, and shared worker scopes
 * to detect spoofing that only patches the main thread. ALSO scores
 * the *availability* of the oracle itself: a real browser running our
 * SDK produces all three scopes (main / web / shared). Submissions
 * that ship fewer scopes either (a) are honest legacy browsers without
 * full worker support — iOS Safari pre-16 famously lacked SharedWorker
 * — or (b) are attackers who learned that patching multiple realms is
 * hard and chose to ship only the main thread. Either way, omission
 * reduces the cross-check's power, and the analyzer surfaces that
 * reduction as a scored signal rather than silently treating absence
 * as innocence (the pre-2026-05 behavior — see ARGUS_URGENT_FIXES #2).
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
 * Codes emitted when the cross-thread oracle is incomplete. Read by
 * `collectTamperingEvidence` in merchant-projection.ts to lift the
 * device-tampering floor for submissions that withheld the oracle.
 *
 *  - WORKER_ORACLE_MAIN_ONLY: zero worker scopes shipped (or no
 *    workerScope object at all). Severity 0.6 → tier-60 in the
 *    tampering ladder ("credible spoof — they withheld the oracle").
 *  - WORKER_ORACLE_NO_SHARED: main + dedicated worker present,
 *    shared worker absent. Severity 0.25 → tier-25 fallback ("minor
 *    tell — could be older Safari, worth flagging"). Reflects iOS
 *    Safari pre-16's lack of SharedWorker, hence the lighter
 *    penalty.
 */
export const WORKER_ORACLE_MAIN_ONLY = "WORKER_ORACLE_MAIN_ONLY";
export const WORKER_ORACLE_NO_SHARED = "WORKER_ORACLE_NO_SHARED";

/** Decide whether the available scope set warrants an oracle-missing signal. */
function oracleMissingSignal(
  scopes: Record<string, unknown> | null,
): { code: string; severity: number; evidence: string } | null {
  const hasWeb = !!(scopes && isObj(scopes.web));
  const hasShared = !!(scopes && isObj(scopes.shared));
  if (hasShared) return null;
  if (hasWeb)
    return {
      code: WORKER_ORACLE_NO_SHARED,
      severity: 0.25,
      evidence: "main+web scopes present; shared worker scope absent",
    };
  return {
    code: WORKER_ORACLE_MAIN_ONLY,
    severity: 0.6,
    evidence: "no dedicated/shared worker scopes shipped",
  };
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
  const scopes = isObj(ws) && isObj(ws.scopes) ? ws.scopes : null;
  const oracleSignal = oracleMissingSignal(scopes);

  // If workerScope is absent entirely we still want the oracle-missing
  // signal (oracleSignal will be WORKER_ORACLE_MAIN_ONLY in that case).
  // Divergence checking only runs when at least main is structured under
  // `scopes`; if it isn't, divergences[] stays empty and the signal
  // carries the score.
  const mainScope = resolveMainScope(scopes, device);
  const divergences = scopes
    ? findDivergences(
        mainScope,
        getScope(scopes, "web"),
        getScope(scopes, "shared"),
      )
    : [];

  const signals = [
    ...formatSignals(anomalySignals),
    ...(oracleSignal ? [oracleSignal] : []),
  ];
  const lied =
    anomalySignals.length > 0 ||
    divergences.length > 0 ||
    oracleSignal !== null;
  return { lied, divergences, signals };
}
