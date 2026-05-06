/**
 * Browser-engine consistency analyzer.
 *
 * Given a session's claimed browser (from UA + sec-ch-ua) and observed
 * engine-invariant fields (jsEngine, layoutEngine, vendor, evalToString
 * length, stack format, window prefixes, etc.), checks the values against
 * the per-(browser, version, incognito) baseline histograms built daily
 * by `browser-baseline-builder` Lambda.
 *
 * Produces two signal kinds:
 *
 *   BROWSER_ENGINE_INCONSISTENT_HARD (sev 0.95) — at least one invariant
 *     field has count=0 for the claimed browser_version, AND that
 *     baseline has accumulated enough samples (n ≥ MIN_HARD_BREAK_N) for
 *     a zero-count to be meaningful. This is the "Safari UA + V8 jsEngine"
 *     case — definitive tampering, feeds device_tampering = 100.
 *
 *   BROWSER_ENGINE_INCONSISTENT_SOFT (sev 0.5) — combined naive-Bayes
 *     log-likelihood under the claimed baseline is below the soft
 *     threshold, but no individual field is impossible. Outlier-but-
 *     possibly-legit; feeds device_tampering = 60.
 *
 * Cold-start fallback chain (ensures no false positives for new browser
 * versions before the aggregator catches up):
 *   1. Exact (browser, version, incognito) baseline → use if present
 *   2. (browser, version, NOT incognito) → drop the incognito split
 *   3. Engine-family baseline (chromium/gecko/webkit) → wide net
 *   4. None of the above → emit no signal (skip analysis)
 *
 * The analyzer never penalizes a session for missing baseline data.
 */

import {
  lookupBrowserBaselineSync,
  lookupEngineFamilyBaselineSync,
  type BrowserBaseline,
} from "../../services/network/browser-baselines";
import { parseUaToBrowser } from "./ua-parser";

/**
 * Minimum baseline sample count before a zero-count value is treated as
 * "structurally impossible" rather than "we just haven't seen it yet."
 * Raise to be more conservative; lower to be more aggressive.
 */
const MIN_HARD_BREAK_N = 1000;

/**
 * Laplace smoothing constant. ε added to count and ε·|distinct_values|
 * added to denominator. A value never seen in the baseline still has
 * non-zero probability for the soft-signal calculation; only the
 * hard-break path uses the raw zero-count check.
 */
const LAPLACE_EPSILON = 0.5;

/**
 * Combined log-likelihood threshold for the soft signal. Sessions whose
 * sum of per-field log-probabilities is below this number relative to a
 * "typical" session of the same browser are flagged. Threshold is
 * deliberately wide; tune from observed distributions later.
 */
const SOFT_SIGNAL_LOG_LIKELIHOOD_THRESHOLD = -8;

/**
 * Same field list as the builder — keep in sync.
 *
 * JS_FIELDS: trained on every clean session; TLS_FIELDS: trained only
 * when the network path doesn't munge TLS (corp shields excluded). At
 * runtime both kinds are checked the same way; the per-field hard-break
 * gate (totalForField ≥ MIN_HARD_BREAK_N) handles the lower-population
 * TLS counts naturally.
 */
const JS_FIELDS = [
  "engine.jsEngine",
  "engine.layoutEngine",
  "engine.evalToStringLength",
  "engine.functionToStringLength",
  "engine.stackFormatHash",
  "navigator.vendor",
  "navigator.oscpuPresent",
  "windowPrefixes.apple",
  "windowPrefixes.moz",
  "windowPrefixes.webkit",
  "css.keyCount",
  "navigator.propertiesLength",
  "headless.chromium",
] as const;

const TLS_FIELDS = [
  "tls.ja4_cipher_hash",
  "tls.h2_pseudo_header_order",
  "tls.h2_protocol",
  "tls.cipher_count",
  "tls.has_grease",
] as const;

const INVARIANT_FIELDS = [...JS_FIELDS, ...TLS_FIELDS] as const;

export interface BrowserEngineSignal {
  code: "BROWSER_ENGINE_INCONSISTENT_HARD" | "BROWSER_ENGINE_INCONSISTENT_SOFT";
  severity: number;
  evidence: string;
}

export interface BrowserEngineAnalysisResult {
  /** Resolved baseline key (e.g. "Chrome 147" or "Chrome 147 incognito"). */
  claimed_key: string | null;
  /** Resolved engine family ("chromium" / "gecko" / "webkit" / null). */
  engine_family: string | null;
  /** Which fallback level we landed on for the comparison. */
  baseline_source:
    | "version"
    | "version_no_incognito"
    | "engine_family"
    | "none";
  /** Sample count of the baseline used. */
  baseline_n: number;
  signals: BrowserEngineSignal[];
}

// ─── Observed-value extraction (from the device block) ──────────────────

function asObj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

function arrayLen(v: unknown): number | null {
  return Array.isArray(v) ? v.length : null;
}

function toScalarOrNull(v: unknown): string | number | boolean | null {
  if (v === null || v === undefined) return null;
  if (
    typeof v === "string" ||
    typeof v === "number" ||
    typeof v === "boolean"
  ) {
    return v;
  }
  return null;
}

interface ObservedTuple {
  [field: string]: string | number | boolean | null;
}

function ja4CipherHash(ja4: unknown): string | null {
  if (typeof ja4 !== "string" || ja4.length === 0) return null;
  const parts = ja4.split("_");
  return parts.length >= 2 ? parts[1] : null;
}

function extractObserved(device: unknown, sigint: unknown): ObservedTuple {
  const d = asObj(device);
  const engine = asObj(d.engine);
  const navigator = asObj(d.navigator);
  const windowPrefixes = asObj(d.windowPrefixes);
  const css = asObj(d.css);
  const headless = asObj(d.headless);
  const s = asObj(sigint);
  const h2 = asObj(s.h2);
  const tcp = asObj(s.tcp_probe);
  const h2Tls = asObj(h2.tls_signals);
  const tcpTls = asObj(tcp.tls_signals);

  return {
    "engine.jsEngine": toScalarOrNull(engine.jsEngine),
    "engine.layoutEngine": toScalarOrNull(engine.layoutEngine),
    "engine.evalToStringLength": toScalarOrNull(engine.evalToStringLength),
    "engine.functionToStringLength": toScalarOrNull(
      engine.functionToStringLength,
    ),
    "engine.stackFormatHash": toScalarOrNull(engine.stackFormatHash),
    "navigator.vendor": toScalarOrNull(navigator.vendor),
    "navigator.oscpuPresent":
      navigator.oscpu !== undefined && navigator.oscpu !== null,
    "windowPrefixes.apple": toScalarOrNull(windowPrefixes.apple),
    "windowPrefixes.moz": toScalarOrNull(windowPrefixes.moz),
    "windowPrefixes.webkit": toScalarOrNull(windowPrefixes.webkit),
    "css.keyCount": toScalarOrNull(css.keyCount),
    "navigator.propertiesLength": arrayLen(navigator.properties),
    "headless.chromium": toScalarOrNull(headless.chromium),
    "tls.ja4_cipher_hash": ja4CipherHash(h2.ja4 ?? tcp.ja4),
    "tls.h2_pseudo_header_order": toScalarOrNull(h2.pseudo_header_order),
    "tls.h2_protocol": toScalarOrNull(h2.protocol),
    "tls.cipher_count":
      toScalarOrNull(h2Tls.cipher_count) ?? toScalarOrNull(tcpTls.cipher_count),
    "tls.has_grease":
      toScalarOrNull(h2Tls.has_grease) ?? toScalarOrNull(tcpTls.has_grease),
  };
}

// ─── Baseline resolution chain ──────────────────────────────────────────

interface ResolvedBaseline {
  baseline: BrowserBaseline;
  source: "version" | "version_no_incognito" | "engine_family";
  key: string;
}

function resolveBaseline(
  browser: string,
  version: string,
  incognito: boolean,
  engineFamily: string,
): ResolvedBaseline | null {
  // 1. Exact key with incognito suffix when applicable.
  const exactKey = `${browser} ${version}${incognito ? " incognito" : ""}`;
  const exact = lookupBrowserBaselineSync(exactKey);
  if (exact && exact.n_sessions > 0) {
    return { baseline: exact, source: "version", key: exactKey };
  }

  // 2. Drop the incognito split if this is an incognito session and the
  //    non-incognito baseline exists. Engine fields shouldn't differ; only
  //    plugin-count and quota would, and those are noisier anyway.
  if (incognito) {
    const noIncogKey = `${browser} ${version}`;
    const noIncog = lookupBrowserBaselineSync(noIncogKey);
    if (noIncog && noIncog.n_sessions > 0) {
      return {
        baseline: noIncog,
        source: "version_no_incognito",
        key: noIncogKey,
      };
    }
  }

  // 3. Engine family fallback (chromium/gecko/webkit unioned across versions).
  const family = lookupEngineFamilyBaselineSync(engineFamily);
  if (family && family.n_sessions > 0) {
    return { baseline: family, source: "engine_family", key: engineFamily };
  }

  return null;
}

// ─── Per-field check (hard break + soft contribution) ───────────────────

interface FieldVerdict {
  field: string;
  observedKey: string;
  /** Count of `observedKey` in the baseline histogram for this field. */
  count: number;
  /** Sum of all counts for this field in the baseline. */
  totalForField: number;
  /** Number of distinct values seen for this field. */
  distinctValues: number;
  /** Naive-Bayes per-field log-prob with Laplace smoothing. */
  logProb: number;
  /** True when count==0 in a well-populated baseline (n ≥ MIN_HARD_BREAK_N). */
  isHardBreak: boolean;
}

function observedKey(value: string | number | boolean | null): string {
  return value === null ? "null" : String(value);
}

function checkField(
  field: string,
  value: string | number | boolean | null,
  baseline: BrowserBaseline,
): FieldVerdict {
  const histogram = baseline.fields[field] ?? {};
  const obsKey = observedKey(value);
  const count = histogram[obsKey] ?? 0;
  const totalForField = Object.values(histogram).reduce((a, b) => a + b, 0);
  const distinctValues = Object.keys(histogram).length;

  // Laplace smoothing: P(value) = (count + ε) / (total + ε·|V|)
  // |V| includes the unseen value, so we add 1 to distinctValues if count==0.
  const denomVocabSize =
    count === 0 ? distinctValues + 1 : Math.max(distinctValues, 1);
  const numerator = count + LAPLACE_EPSILON;
  const denominator = totalForField + LAPLACE_EPSILON * denomVocabSize;
  const prob = denominator > 0 ? numerator / denominator : 0;
  const logProb = prob > 0 ? Math.log(prob) : Number.NEGATIVE_INFINITY;

  // Gate hard-break on the PER-FIELD population, not the baseline as a
  // whole. TLS fields may have far fewer observations than JS fields
  // (corp-shielded sessions contribute JS but not TLS), and a brand-new
  // field added to the schema starts at totalForField=0 across an
  // otherwise-mature baseline. Either case → don't fire spurious breaks.
  const isHardBreak = count === 0 && totalForField >= MIN_HARD_BREAK_N;

  return {
    field,
    observedKey: obsKey,
    count,
    totalForField,
    distinctValues,
    logProb,
    isHardBreak,
  };
}

// ─── Signal builders (per category) ──────────────────────────────────────

function buildHardBreakSignal(
  verdicts: FieldVerdict[],
  resolved: ResolvedBaseline,
  claimedKey: string,
): BrowserEngineSignal | null {
  // Hard breaks only count when the baseline is well-populated. Engine-
  // family fallback with small n is too coarse for "structurally
  // impossible" claims; require a much larger sample there.
  const allowHardBreak =
    resolved.source !== "engine_family" ||
    resolved.baseline.n_sessions >= MIN_HARD_BREAK_N * 5;
  if (!allowHardBreak) return null;
  const hardBreaks = verdicts.filter((v) => v.isHardBreak);
  if (hardBreaks.length === 0) return null;
  const evidence = hardBreaks
    .map(
      (v) =>
        `${v.field}=${v.observedKey} (0/${v.totalForField} in ${resolved.key})`,
    )
    .join("; ");
  return {
    code: "BROWSER_ENGINE_INCONSISTENT_HARD",
    severity: 0.95,
    evidence: `claimed=${claimedKey}; ${evidence}`,
  };
}

function buildSoftSignal(
  verdicts: FieldVerdict[],
  resolved: ResolvedBaseline,
  claimedKey: string,
): BrowserEngineSignal | null {
  // Cold-start protection (1): never fire from the engine-family fallback.
  // Family baselines aggregate multiple browser versions whose invariants
  // legitimately differ (e.g. css.keyCount = 382 for Firefox 149, 383 for
  // Firefox 150) — every real session looks like an outlier against the
  // bimodal family histogram. Hard breaks still work on family fallback
  // because they gate on count=0 (truly impossible), but soft requires
  // a single-version baseline to calibrate against.
  if (resolved.source === "engine_family") return null;
  // Cold-start protection (2): below MIN_HARD_BREAK_N samples, the
  // Laplace-smoothing math produces a baseline-low logL even for matching
  // values (per-field logP ≈ log(1/n) summed across ~18 fields). Without
  // this gate, sparse baselines fire soft signals from smoothing noise
  // alone, not from real outliers.
  if (resolved.baseline.n_sessions < MIN_HARD_BREAK_N) return null;

  const logLikelihood = verdicts.reduce(
    (acc, v) => acc + (Number.isFinite(v.logProb) ? v.logProb : -20),
    0,
  );
  if (logLikelihood >= SOFT_SIGNAL_LOG_LIKELIHOOD_THRESHOLD) return null;
  const outliers = verdicts
    .filter((v) => v.logProb < -3) // < ~5% probability per field
    .map((v) => `${v.field}=${v.observedKey}`)
    .join("; ");
  return {
    code: "BROWSER_ENGINE_INCONSISTENT_SOFT",
    severity: 0.5,
    evidence: `claimed=${claimedKey}; logL=${logLikelihood.toFixed(2)}; outliers=[${outliers}]`,
  };
}

function emptyResult(
  claimedKey: string | null,
  engineFamily: string | null,
): BrowserEngineAnalysisResult {
  return {
    claimed_key: claimedKey,
    engine_family: engineFamily,
    baseline_source: "none",
    baseline_n: 0,
    signals: [],
  };
}

// ─── Top-level analyzer ──────────────────────────────────────────────────

export interface BrowserEngineAnalysisInput {
  device: unknown;
  sigint: unknown;
  ua: string | null;
  secChUa: string | null;
  incognito: boolean;
}

export function analyzeBrowserEngine(
  input: BrowserEngineAnalysisInput,
): BrowserEngineAnalysisResult {
  const { device, sigint, ua, secChUa, incognito } = input;
  const claimed = parseUaToBrowser(ua, secChUa);
  if (!claimed) return emptyResult(null, null);

  const claimedKey = `${claimed.browser} ${claimed.version}${incognito ? " incognito" : ""}`;
  const resolved = resolveBaseline(
    claimed.browser,
    claimed.version,
    incognito,
    claimed.engineFamily,
  );
  if (!resolved) return emptyResult(claimedKey, claimed.engineFamily);

  const observed = extractObserved(device, sigint);
  const verdicts = INVARIANT_FIELDS.map((field) =>
    checkField(field, observed[field], resolved.baseline),
  );

  const signals: BrowserEngineSignal[] = [];
  const hard = buildHardBreakSignal(verdicts, resolved, claimedKey);
  if (hard) signals.push(hard);
  // Soft only fires when no hard break (would be redundant in the projector).
  if (signals.length === 0) {
    const soft = buildSoftSignal(verdicts, resolved, claimedKey);
    if (soft) signals.push(soft);
  }

  return {
    claimed_key: claimedKey,
    engine_family: claimed.engineFamily,
    baseline_source: resolved.source,
    baseline_n: resolved.baseline.n_sessions,
    signals,
  };
}
