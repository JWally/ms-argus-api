/**
 * Client-hints / User-Agent cross-verification.
 *
 * Four cross-checks:
 *   1. sec-ch-ua-platform vs UA-inferred OS
 *   2. sec-ch-ua-mobile   vs UA-inferred mobile/desktop
 *   3. sec-ch-ua          vs UA-inferred browser family (Chrome/Edge/etc.)
 *   4. tcp_probe.client_hints vs request_headers.sec-ch-ua*  (twin capture)
 *
 * All four only apply to Chromium-family UAs. Firefox and Safari don't
 * emit Sec-CH-UA* in most configurations; the "claims Chromium but no
 * Sec-CH-UA" case is already handled by detectUaFamilyHeaderMismatch in
 * merchant-projection.
 *
 * Twin-capture (#4) is the strongest signal — the same browser should
 * report identical client hints to the H2 probe and the /v1/integrity-
 * collect endpoint. Disagreement is proof of mid-session rotation
 * (fingerprint profile swap, proxy chain switch, anti-detect session
 * rotation). No benign explanation.
 */

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Strip wrapping double-quotes that Chromium emits around string values. */
function unquote(v: string | null): string | null {
  if (!v) return null;
  const m = v.match(/^"(.*)"$/);
  return m ? m[1] : v;
}

type Os =
  | "Windows"
  | "macOS"
  | "iOS"
  | "Android"
  | "Linux"
  | "Chrome OS"
  | "Unknown";

type BrowserFamily = "chromium" | "edge" | "other";

/**
 * Derive OS from the Sec-CH-UA-Platform header value. Order matters —
 * "chromeos"/"chrome os" must match before "linux" because ChromeOS is
 * technically Linux-based. "ios"/"ipad" must match before any generic
 * Mac token.
 */
const CH_PLATFORM_PATTERNS: readonly (readonly [RegExp, Os])[] = [
  [/windows/, "Windows"],
  [/ios|ipad/, "iOS"],
  [/android/, "Android"],
  [/chrome\s*os/, "Chrome OS"],
  [/macos|^mac$/, "macOS"],
  [/linux/, "Linux"],
];

function platformFromCh(value: string | null): Os | null {
  const v = unquote(value);
  if (!v) return null;
  const norm = v.toLowerCase();
  for (const [re, os] of CH_PLATFORM_PATTERNS) {
    if (re.test(norm)) return os;
  }
  return "Unknown";
}

/**
 * Derive OS from a UA string. Order matters — iOS tokens come before
 * Mac because iOS UAs often include both "iPhone" and "like Mac OS X".
 * Android UAs include "Linux" and must match before the Linux rule.
 */
const UA_PLATFORM_PATTERNS: readonly (readonly [RegExp, Os])[] = [
  [/iPhone|iPad|iPod/, "iOS"],
  [/Android/, "Android"],
  [/Macintosh|Mac OS X/, "macOS"],
  [/CrOS/, "Chrome OS"],
  [/Windows/, "Windows"],
  [/X11|Linux/, "Linux"],
];

function platformFromUa(ua: string | null): Os | null {
  if (!ua) return null;
  for (const [re, os] of UA_PLATFORM_PATTERNS) {
    if (re.test(ua)) return os;
  }
  return null;
}

function mobileFromCh(value: string | null): boolean | null {
  if (!value) return null;
  if (value === "?1") return true;
  if (value === "?0") return false;
  return null;
}

function mobileFromUa(ua: string | null): boolean | null {
  if (!ua) return null;
  return /iPhone|iPod|Android|Mobile/.test(ua);
}

function familyFromUa(ua: string | null): BrowserFamily {
  if (!ua) return "other";
  // Edge UA tokens across platforms:
  //   `Edge/`   — legacy EdgeHTML (pre-Chromium)
  //   `Edg/`    — Chromium-based Edge desktop (Windows / macOS / Linux) ← was missing
  //   `EdgA/`   — Edge on Android
  //   `EdgiOS/` — Edge on iOS
  // Without the trailing-suffix group being optional, modern desktop Edge
  // (overwhelmingly the most common form in 2026) fell through to the
  // Chrome\/\d check below and was classified as `chromium`. The brand
  // parser correctly returned `edge` from "Microsoft Edge", which then
  // mismatched the UA family and fired CH_UA_BRAND_MISMATCH on every real
  // Edge desktop visitor.
  if (/Edg(e|A|iOS)?\//.test(ua)) return "edge";
  if (/Chrome\/\d/.test(ua)) return "chromium";
  return "other";
}

/**
 * Parse a Sec-CH-UA brand list like:
 *   "Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"
 * Returns the brand names (not the GREASE ones).
 */
export function parseChUaBrands(raw: string | null | undefined): string[] {
  if (!raw) return [];
  const brands: string[] = [];
  const re = /"([^"]+)";v="([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const name = m[1];
    // Skip GREASE brands (variable unknowns like "Not A Brand", "Not?A_Brand").
    if (/^Not[^A-Za-z0-9]+A.?Brand$/i.test(name)) continue;
    brands.push(name);
  }
  return brands;
}

function familyFromChBrands(brands: string[]): BrowserFamily {
  const lower = brands.map((b) => b.toLowerCase());
  if (lower.some((b) => b.includes("edge"))) return "edge";
  if (lower.some((b) => b.includes("chromium") || b.includes("chrome")))
    return "chromium";
  return "other";
}

export type ClientHintsUaSignalCode =
  | "CH_UA_PLATFORM_MISMATCH"
  | "CH_UA_MOBILE_MISMATCH"
  | "CH_UA_BRAND_MISMATCH"
  | "CH_DOUBLE_CAPTURE_MISMATCH";

export interface ClientHintsUaSignal {
  code: ClientHintsUaSignalCode;
  severity: number;
  evidence: string;
}

export interface ClientHintsUaAnalysisResult {
  signals: ClientHintsUaSignal[];
  /** Convenience: any signal >= 0.8 — feeds the tamper ladder. */
  hasStrongMismatch: boolean;
}

interface ChSources {
  /** From request_headers captured at /v1/integrity-collect. */
  headerUa: string | null;
  headerPlatform: string | null;
  headerMobile: string | null;
  /** From sigint.tcp_probe.client_hints (captured at the H2 probe endpoint). */
  probeUa: string | null;
  probePlatform: string | null;
  probeMobile: string | null;
}

function readSources(
  requestHeaders: Record<string, string> | null,
  tcpProbe: unknown,
): ChSources {
  const h = requestHeaders ?? {};
  const probe =
    isObj(tcpProbe) && isObj(tcpProbe.client_hints)
      ? tcpProbe.client_hints
      : {};
  return {
    headerUa: str(h["sec-ch-ua"]),
    headerPlatform: str(h["sec-ch-ua-platform"]),
    headerMobile: str(h["sec-ch-ua-mobile"]),
    probeUa: str((probe as Record<string, unknown>).ua),
    probePlatform: str((probe as Record<string, unknown>).ua_platform),
    probeMobile: str((probe as Record<string, unknown>).ua_mobile),
  };
}

/** #1 — platform header vs UA OS. */
function checkPlatformVsUa(
  sources: ChSources,
  ua: string | null,
): ClientHintsUaSignal | null {
  const chPlatform = platformFromCh(
    sources.headerPlatform ?? sources.probePlatform,
  );
  const uaPlatform = platformFromUa(ua);
  if (!chPlatform || chPlatform === "Unknown" || !uaPlatform) return null;
  if (chPlatform === uaPlatform) return null;
  return {
    code: "CH_UA_PLATFORM_MISMATCH",
    severity: 0.85,
    evidence: `sec-ch-ua-platform=${chPlatform} vs UA=${uaPlatform}`,
  };
}

/** #2 — mobile header vs UA mobility. */
function checkMobileVsUa(
  sources: ChSources,
  ua: string | null,
): ClientHintsUaSignal | null {
  const chMobile = mobileFromCh(sources.headerMobile ?? sources.probeMobile);
  const uaMobile = mobileFromUa(ua);
  if (chMobile === null || uaMobile === null) return null;
  if (chMobile === uaMobile) return null;
  return {
    code: "CH_UA_MOBILE_MISMATCH",
    severity: 0.8,
    evidence: `sec-ch-ua-mobile=${chMobile ? "?1" : "?0"} vs UA-mobile=${uaMobile}`,
  };
}

/** #3 — Sec-CH-UA brand list vs UA browser family. */
function checkBrandVsUa(
  sources: ChSources,
  ua: string | null,
): ClientHintsUaSignal | null {
  const raw = sources.headerUa ?? sources.probeUa;
  if (!raw) return null;
  const brandFamily = familyFromChBrands(parseChUaBrands(raw));
  if (brandFamily === "other") return null;
  const uaFamily = familyFromUa(ua);
  if (uaFamily === "other") return null;
  if (brandFamily === uaFamily) return null;
  return {
    code: "CH_UA_BRAND_MISMATCH",
    severity: 0.9,
    evidence: `sec-ch-ua=${brandFamily} vs UA=${uaFamily}`,
  };
}

function diffStr(
  label: string,
  a: string | null,
  b: string | null,
): string | null {
  if (!a || !b || a === b) return null;
  return `${label}: header=${a} probe=${b}`;
}

function diffBrandFamily(
  headerUa: string | null,
  probeUa: string | null,
): string | null {
  if (!headerUa || !probeUa) return null;
  const hb = familyFromChBrands(parseChUaBrands(headerUa));
  const pb = familyFromChBrands(parseChUaBrands(probeUa));
  if (hb === "other" || pb === "other" || hb === pb) return null;
  return `ua: header=${hb} probe=${pb}`;
}

/**
 * #4 — Double-capture disagreement. When both the H2 probe and the
 * integrity-collect request captured client hints, they must match.
 */
function checkDoubleCaptureMismatch(
  sources: ChSources,
): ClientHintsUaSignal | null {
  const mismatches = [
    diffStr("platform", sources.headerPlatform, sources.probePlatform),
    diffStr("mobile", sources.headerMobile, sources.probeMobile),
    diffBrandFamily(sources.headerUa, sources.probeUa),
  ].filter((x): x is string => x !== null);
  if (mismatches.length === 0) return null;
  return {
    code: "CH_DOUBLE_CAPTURE_MISMATCH",
    severity: 0.9,
    evidence: mismatches.join("; "),
  };
}

/** Main entry. */
export function analyzeClientHintsUa(
  ua: string | null,
  requestHeaders: Record<string, string> | null,
  tcpProbe: unknown,
): ClientHintsUaAnalysisResult {
  const sources = readSources(requestHeaders, tcpProbe);
  const signals: ClientHintsUaSignal[] = [];

  const s1 = checkPlatformVsUa(sources, ua);
  if (s1) signals.push(s1);
  const s2 = checkMobileVsUa(sources, ua);
  if (s2) signals.push(s2);
  const s3 = checkBrandVsUa(sources, ua);
  if (s3) signals.push(s3);
  const s4 = checkDoubleCaptureMismatch(sources);
  if (s4) signals.push(s4);

  return {
    signals,
    hasStrongMismatch: signals.some((s) => s.severity >= 0.8),
  };
}
