/**
 * Worker scope divergence analysis for integrity ingestion.
 *
 * Compares main-thread, dedicated worker, and shared worker scopes
 * to detect spoofing that only patches the main thread. ALSO scores
 * the *availability* of the oracle itself: a real browser running our
 * SDK produces a worker scope alongside main. Submissions that ship
 * zero worker scopes either (a) are running an unusual browser
 * configuration that doesn't support Worker at all (rare in 2026) or
 * (b) are attackers who learned that patching multiple realms is hard
 * and chose to ship only the main thread.
 *
 * Note on shared workers: an earlier iteration ALSO penalized
 * "main+dedicated, no shared" but that produced false positives on
 * every legitimate Android Chrome session (Chromium intentionally
 * never shipped SharedWorker on Android) and pre-iOS-16 Safari. The
 * production rule is now: any worker (dedicated OR shared) present is
 * sufficient for the cross-thread divergence check; only the
 * zero-workers case scores. See ARGUS_URGENT_FIXES #2.
 */

import { detectCrossFieldAnomalies } from "../../services/profile/anomaly/worker-scope-consistency";
import { toResultSignals } from "../../services/profile/anomaly/types";
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
  return toResultSignals(signals);
}

/**
 * Code emitted when the cross-thread oracle is incomplete. Read by
 * `collectTamperingEvidence` in merchant-projection.ts to lift the
 * device-tampering floor for submissions that withheld the oracle.
 *
 * WORKER_ORACLE_MAIN_ONLY fires when NEITHER `scopes.web` (dedicated
 * worker) NOR `scopes.shared` (shared worker) is present — i.e. zero
 * worker scopes, or no `workerScope` object at all. Severity 0.5 →
 * tier-50 in the tampering ladder (same slot as `iframeCryptoStuck`).
 *
 * Earlier iterations also emitted WORKER_ORACLE_NO_SHARED for the
 * "main + dedicated, no shared" case, but that fired on every
 * legitimate Android Chrome session (Chromium intentionally never
 * shipped SharedWorker on Android) and pre-iOS-16 Safari. The
 * production rule is now: ANY worker (dedicated or shared) present
 * means the oracle is sufficient to trust the cross-thread divergence
 * check; only zero-workers is a tell.
 */
export const WORKER_ORACLE_MAIN_ONLY = "WORKER_ORACLE_MAIN_ONLY";

/** Decide whether the available scope set warrants an oracle-missing signal. */
function oracleMissingSignal(
  scopes: Record<string, unknown> | null,
): { code: string; severity: number; evidence: string } | null {
  const hasWeb = !!(scopes && isObj(scopes.web));
  const hasShared = !!(scopes && isObj(scopes.shared));
  if (hasWeb || hasShared) return null;
  return {
    code: WORKER_ORACLE_MAIN_ONLY,
    severity: 0.5,
    evidence: "no dedicated or shared worker scopes shipped",
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
