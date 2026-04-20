/**
 * Locale / geo cross-verification.
 *
 * Cross-checks three independent surfaces:
 *   1. Intra-client locale consistency (intl vs navigator vs worker)
 *   2. Accept-Language header vs IP geolocation country
 *
 * Complements `analyze-timezone`, which covers TZ offset/location. Both
 * feed the same tampering ladder in merchant-projection.
 *
 * Severities use the established scale:
 *   0.85+ = near-proof tamper (real browsers don't disagree here)
 *   0.6–0.75 = strong signal, some benign FPs (travelers, expats)
 *   0.4 = weak signal, informational
 */

import {
  COUNTRY_TO_CONTINENT,
  CONTINENT_NAME,
  LANG_TO_COUNTRIES,
  parseAcceptLanguage,
} from "./reference";

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

export type LocaleGeoSignalCode =
  | "LOCALE_NAV_INTL_MISMATCH"
  | "LOCALE_WORKER_MAIN_MISMATCH"
  | "ACCEPT_LANG_GEO_CROSS_CONTINENT"
  | "ACCEPT_LANG_GEO_CROSS_COUNTRY";

export interface LocaleGeoSignal {
  code: LocaleGeoSignalCode;
  severity: number;
  evidence: string;
}

export interface LocaleGeoAnalysisResult {
  signals: LocaleGeoSignal[];
  /** Convenience: true if any signal scored >= 0.6. */
  hasLocationMismatch: boolean;
  /** Convenience: true if any internal-locale mismatch fired. */
  hasLocaleTamper: boolean;
}

/** Extract the two-letter language code from a locale-ish string. */
function langPart(s: string | null): string | null {
  if (!s) return null;
  const m = s.toLowerCase().match(/^([a-z]{2,3})\b/);
  return m ? m[1] : null;
}

/** Extract navigator.language's primary language. Format is e.g. "en-US (en-US)". */
function navigatorLang(device: Record<string, unknown>): string | null {
  const nav = isObj(device.navigator) ? device.navigator : null;
  const raw = nav ? str(nav.language) : null;
  if (!raw) return null;
  // navigator.language in our payload is formatted "en-US (en-US)".
  const stripped = raw.split(/[\s(]/)[0];
  return stripped || null;
}

function intlLocale(device: Record<string, unknown>): string | null {
  const intl = isObj(device.intl) ? device.intl : null;
  return intl ? str(intl.locale) : null;
}

function scopeLocale(
  scopes: Record<string, unknown>,
  key: string,
): string | null {
  const scope = isObj(scopes[key]) ? scopes[key] : null;
  return scope ? str(scope.locale) : null;
}

function workerLocales(device: Record<string, unknown>): string[] {
  const ws = isObj(device.workerScope) ? device.workerScope : null;
  const scopes = ws && isObj(ws.scopes) ? ws.scopes : null;
  if (!scopes) return [];
  return ["web", "shared", "dedicated"]
    .map((k) => scopeLocale(scopes, k))
    .filter((v): v is string => v !== null);
}

/**
 * A1 — intl.locale's language doesn't match navigator.language's primary.
 * Both are JS surfaces; real browsers always agree on the language part.
 */
function checkIntlVsNavigator(
  device: Record<string, unknown>,
): LocaleGeoSignal | null {
  const intl = intlLocale(device);
  const nav = navigatorLang(device);
  if (!intl || !nav) return null;
  const a = langPart(intl);
  const b = langPart(nav);
  if (!a || !b || a === b) return null;
  return {
    code: "LOCALE_NAV_INTL_MISMATCH",
    severity: 0.85,
    evidence: `intl.locale=${intl}, navigator.language=${nav}`,
  };
}

/**
 * A2 — main-thread locale doesn't match at least one worker scope locale.
 * Anti-detect browsers frequently forget to spoof the worker's locale.
 */
function checkWorkerVsMain(
  device: Record<string, unknown>,
): LocaleGeoSignal | null {
  const main = intlLocale(device) ?? navigatorLang(device);
  if (!main) return null;
  const mainLang = langPart(main);
  if (!mainLang) return null;
  const workers = workerLocales(device);
  if (workers.length === 0) return null;
  const mismatches = workers.filter((w) => langPart(w) !== mainLang);
  if (mismatches.length === 0) return null;
  return {
    code: "LOCALE_WORKER_MAIN_MISMATCH",
    severity: 0.75,
    evidence: `main=${main}, worker=[${mismatches.join(",")}]`,
  };
}

/**
 * B1 — primary Accept-Language vs IP geolocation country. Graded by
 * geographic distance:
 *   - cross-continent mismatch → 0.7
 *   - same-continent, different country → 0.4
 *
 * Skips when the header is absent or the parsed country matches CF country.
 */
function checkAcceptLangVsCountry(
  acceptLanguage: string | null,
  cfCountry: string | null,
): LocaleGeoSignal | null {
  if (!acceptLanguage || !cfCountry) return null;
  const parsed = parseAcceptLanguage(acceptLanguage);
  if (!parsed) return null;

  // Ignore neutral prefixes like "en" without a country subtag and without
  // a narrow language→country mapping — ambiguous, not a tell on its own.
  const cf = cfCountry.toUpperCase();

  // If the header explicitly included a country, compare it directly.
  if (parsed.country) {
    if (parsed.country === cf) return null;
    return gradeCountryMismatch(parsed.lang, parsed.country, cf);
  }

  // No country in header — use language→country plausibility set.
  const plausible = LANG_TO_COUNTRIES[parsed.lang];
  if (!plausible) return null; // unknown language, no assertion
  if (plausible.includes(cf)) return null;

  // Pick the most populous plausible country to report.
  const claimed = plausible[0];
  return gradeCountryMismatch(parsed.lang, claimed, cf);
}

function gradeCountryMismatch(
  lang: string,
  claimedCountry: string,
  actualCountry: string,
): LocaleGeoSignal {
  const claimedCont = COUNTRY_TO_CONTINENT[claimedCountry];
  const actualCont = COUNTRY_TO_CONTINENT[actualCountry];
  const crossContinent =
    claimedCont && actualCont && claimedCont !== actualCont;
  const evidence = `accept-language=${lang}-${claimedCountry} (${CONTINENT_NAME[claimedCont ?? ""] ?? "?"}) vs ip_country=${actualCountry} (${CONTINENT_NAME[actualCont ?? ""] ?? "?"})`;
  return {
    code: crossContinent
      ? "ACCEPT_LANG_GEO_CROSS_CONTINENT"
      : "ACCEPT_LANG_GEO_CROSS_COUNTRY",
    severity: crossContinent ? 0.7 : 0.4,
    evidence,
  };
}

/** Main entry — runs all checks, returns signals + convenience booleans. */
export function analyzeLocaleGeo(
  device: unknown,
  acceptLanguage: string | null,
  cfCountry: string | null,
): LocaleGeoAnalysisResult {
  const signals: LocaleGeoSignal[] = [];
  if (isObj(device)) {
    const s1 = checkIntlVsNavigator(device);
    if (s1) signals.push(s1);
    const s2 = checkWorkerVsMain(device);
    if (s2) signals.push(s2);
  }
  const s3 = checkAcceptLangVsCountry(acceptLanguage, cfCountry);
  if (s3) signals.push(s3);

  return {
    signals,
    hasLocationMismatch: signals.some(
      (s) =>
        s.code === "ACCEPT_LANG_GEO_CROSS_CONTINENT" ||
        s.code === "ACCEPT_LANG_GEO_CROSS_COUNTRY",
    ),
    hasLocaleTamper: signals.some(
      (s) =>
        s.code === "LOCALE_NAV_INTL_MISMATCH" ||
        s.code === "LOCALE_WORKER_MAIN_MISMATCH",
    ),
  };
}
