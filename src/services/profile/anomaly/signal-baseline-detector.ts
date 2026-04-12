/**
 * Signal Baseline Detector
 *
 * Population-based anomaly detection: compares signal hashes from the
 * current request against learned baselines for the browser version.
 * If a baseline is locked (100+ observations) and the hash is not in
 * the known-good set, it's flagged as rare.
 *
 * Replaces hardcoded reference tables with self-learning population model.
 *
 * @module services/profile/anomaly/signal-baseline-detector
 */

import type { CachedBaseline } from "../../signal-learning";
import {
  AnomalySignal,
  AnomalyCodes,
  AnomalyCode,
  createSignal,
} from "./types";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

/** Map signal module names to their anomaly codes. */
const MODULE_CODES: Record<string, AnomalyCode> = {
  math: AnomalyCodes.RARE_MATHS_FOR_UA,
  eval_length: AnomalyCodes.RARE_EVAL_LENGTH_FOR_UA,
  css_key_count: AnomalyCodes.RARE_CSS_KEY_COUNT_FOR_UA,
  window_moz: AnomalyCodes.RARE_WINDOW_PREFIX_FOR_UA,
  worker_nav_props: AnomalyCodes.RARE_WORKER_NAV_PROPS_FOR_UA,
};

// --- Per-module hash extractors -------------------------------------------

function getSubObj(
  device: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  return device[key] as Record<string, unknown> | undefined;
}

function extractMathHash(device: Record<string, unknown>): string | null {
  const math = getSubObj(device, "math");
  return typeof math?.hash === "string" ? math.hash : null;
}

function extractEvalLength(device: Record<string, unknown>): string | null {
  const engine = getSubObj(device, "engine");
  return typeof engine?.evalToStringLength === "number"
    ? String(engine.evalToStringLength)
    : null;
}

function extractCssKeyCount(device: Record<string, unknown>): string | null {
  const css = getSubObj(device, "css");
  return typeof css?.keyCount === "number" ? String(css.keyCount) : null;
}

function extractWindowMoz(device: Record<string, unknown>): string | null {
  const wp = getSubObj(device, "windowPrefixes");
  return typeof wp?.moz === "number" ? String(wp.moz) : null;
}

function scopePropCount(
  scope: Record<string, unknown> | undefined,
): string | null {
  return typeof scope?.navigatorPropertyCount === "number"
    ? String(scope.navigatorPropertyCount)
    : null;
}

function extractWorkerNavProps(device: Record<string, unknown>): string | null {
  const ws = getSubObj(device, "workerScope");
  if (!ws) return null;
  const scopes = ws.scopes as Record<string, unknown> | undefined;
  const shared = scopePropCount(
    scopes?.shared as Record<string, unknown> | undefined,
  );
  if (shared !== null) return shared;
  const web = scopePropCount(
    scopes?.web as Record<string, unknown> | undefined,
  );
  if (web !== null) return web;
  return scopePropCount(ws);
}

const HASH_EXTRACTORS: Record<
  string,
  (d: Record<string, unknown>) => string | null
> = {
  math: extractMathHash,
  eval_length: extractEvalLength,
  css_key_count: extractCssKeyCount,
  window_moz: extractWindowMoz,
  worker_nav_props: extractWorkerNavProps,
};

/** Extract the signal hash for a module from the device payload. */
function extractHash(
  device: Record<string, unknown>,
  module: string,
): string | null {
  const fn = HASH_EXTRACTORS[module];
  return fn ? fn(device) : null;
}

/** Build one baseline-divergence signal, if the observed hash is unknown. */
function maybeBuildSignal(
  module: string,
  baseline: CachedBaseline,
  device: Record<string, unknown>,
): AnomalySignal | null {
  if (!baseline.locked || !baseline.lockedHashes) return null;
  const code = MODULE_CODES[module];
  if (!code) return null;
  const hash = extractHash(device, module);
  if (hash === null) return null;
  if (baseline.lockedHashes.has(hash)) return null;
  return createSignal("STATISTICAL", code, 0.9, {
    expected: `${module} hash in learned baseline`,
    actual: `hash "${hash}" not in population baseline (${baseline.lockedHashes.size} known)`,
    fields: [`device.${module}`],
  });
}

/**
 * Detect signal baseline anomalies.
 *
 * For each signal module with a locked baseline, checks whether the
 * current request's hash is in the known-good set. Unknown hashes
 * in locked baselines are flagged as rare with high severity.
 *
 * Unlocked baselines (still learning) produce no signals.
 */
export function detectSignalBaselines(
  raw: unknown,
  baselines: Map<string, CachedBaseline> | undefined,
): AnomalySignal[] {
  if (!baselines) return [];
  const device = isObj(raw) ? raw : {};
  const signals: AnomalySignal[] = [];
  for (const [module, baseline] of baselines) {
    const sig = maybeBuildSignal(module, baseline, device);
    if (sig) signals.push(sig);
  }
  return signals;
}
