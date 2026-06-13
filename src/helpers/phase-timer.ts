/**
 * Lightweight per-phase timing for the integrity-collect hot path.
 *
 * Emits one structured Powertools-logger line per request breaking the handler
 * duration into phases (hydrate / identity / device-history / analysis /
 * velocity / persist), so we can rank choke points via Logs Insights
 * (e.g. `filter msg="phase_timing" | stats avg(persist_ms), pct(analysis_ms,99)`).
 *
 * Gating (see phaseTimingEnabled): the CDK sets `PHASE_TIMING` per stage —
 * "true" in non-prod (on by default), "false" in prod. To turn it on in prod
 * temporarily, set the Lambda's PHASE_TIMING env var to "true" (a function
 * config update — no redeploy). Zero deps, no X-Ray/@smithy bundling risk, and
 * the marks are a couple of Date.now() calls (negligible even when on).
 */

/**
 * On only when PHASE_TIMING is explicitly truthy. The CDK env default makes
 * that the case in non-prod; prod is "false" until someone flips the env var.
 * Unset (tests / local) → off, so nothing is emitted in unit tests.
 */
export function phaseTimingEnabled(): boolean {
  const flag = process.env.PHASE_TIMING;
  return flag === "true" || flag === "1";
}

export interface PhaseTimer {
  /** Record the elapsed ms since the previous mark under `<name>_ms`. */
  mark(name: string): void;
  /** Record an explicit duration under `<name>_ms` (for parallel sub-tasks
   *  where the sequential delta from mark() doesn't apply). */
  record(name: string, ms: number): void;
  /** All recorded phase deltas, plus total_ms since the timer was created. */
  summary(): Record<string, number>;
}

export function makePhaseTimer(): PhaseTimer {
  const t0 = Date.now();
  let last = t0;
  const phases: Record<string, number> = {};
  return {
    mark(name: string): void {
      const now = Date.now();
      phases[`${name}_ms`] = now - last;
      last = now;
    },
    record(name: string, ms: number): void {
      phases[`${name}_ms`] = ms;
    },
    summary(): Record<string, number> {
      return { ...phases, total_ms: Date.now() - t0 };
    },
  };
}

/**
 * Await `p`, recording its own elapsed ms under `<name>_ms`. Use to break down
 * a Promise.all group where each branch needs individual timing. Records even
 * if `p` rejects (the rejection still propagates).
 */
export async function timeAsync<T>(
  pt: PhaseTimer,
  name: string,
  p: Promise<T>,
): Promise<T> {
  const t = Date.now();
  try {
    return await p;
  } finally {
    pt.record(name, Date.now() - t);
  }
}
