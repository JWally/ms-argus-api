/**
 * JA4/H2 vs UA cross-validation for integrity ingestion.
 *
 * Uses TLS cipher hash and H2 pseudo-header order as ground truth
 * to verify the browser family claimed in the User-Agent string.
 * Reference tables derived from observed production traffic (2026-04).
 *
 * Browser family detection is reliable from either signal alone.
 * Safari cipher hashes additionally distinguish iOS vs macOS.
 */

// -- Reference tables (proven from observed traffic) --

/** JA4 cipher hash (12-char hex, 2nd segment) → browser family. */
const CIPHER_HASH_FAMILY: Record<string, string> = {
  "8daaf6152771": "chromium", // BoringSSL
  e72c3b3287f1: "chromium", // BoringSSL-Edge
  "55b375c5d22e": "chromium", // BoringSSL-QUIC
  "66859890b71d": "chromium", // BoringSSL-QUIC-Edge
  "5b57614c22b0": "firefox", // NSS
  a09f3c656075: "safari", // SecureTransport (iOS)
  "723694b0fccc": "safari", // SecureTransport (macOS)
  "2802a3db6c62": "safari", // SecureTransport-legacy
};

/** Safari cipher hashes that distinguish iOS from macOS. */
const SAFARI_OS: Record<string, string> = {
  // a09f3c656075 is shared between iOS and macOS — not OS-specific
  "2802a3db6c62": "iOS",
  "723694b0fccc": "macOS",
};

/** H2 pseudo-header order → browser family. */
const H2_PSEUDO_FAMILY: Record<string, string> = {
  "m,a,s,p": "chromium",
  "m,s,a,p": "safari",
  "m,s,p,a": "safari",
  "m,p,a,s": "firefox",
};

/** UA substring → browser family. */
const UA_FAMILY_PATTERNS: [RegExp, string][] = [
  [/EdgiOS|Edg\//i, "chromium"],
  [/FxiOS/i, "safari"], // Firefox on iOS uses Safari TLS
  [/CriOS/i, "safari"], // Chrome on iOS uses Safari TLS
  [/Firefox\//i, "firefox"],
  [/Chrome\//i, "chromium"],
  [/Safari\//i, "safari"],
];

/** UA substring → OS. */
const UA_OS_PATTERNS: [RegExp, string][] = [
  [/iPhone|iPad|iPod/i, "iOS"],
  [/Macintosh|Mac OS X/i, "macOS"],
  [/Windows/i, "Windows"],
  [/Android/i, "Android"],
  [/CrOS/i, "Chrome OS"],
  [/Linux/i, "Linux"],
];

// -- Types --

interface Ja4UaSignal {
  code: string;
  severity: number;
  expected: string;
  actual: string;
}

export interface Ja4UaAnalysisResult {
  ja4_browser_family: string | null;
  h2_browser_family: string | null;
  ua_browser_family: string | null;
  ua_os: string | null;
  signals: Ja4UaSignal[];
}

/** Resolved signals from sigint and UA for rule checking. */
interface ResolvedSignals {
  ja4Family: string | null;
  h2Family: string | null;
  h2Pseudo: string | null;
  cipherHash: string | null;
  uaBrowser: string | null;
  uaOs: string | null;
}

// -- Helpers --

function parseCipherHash(ja4: string): string | null {
  const parts = ja4.split("_");
  return parts.length >= 2 ? parts[1] : null;
}

function uaFamily(ua: string): string | null {
  for (const [re, family] of UA_FAMILY_PATTERNS) {
    if (re.test(ua)) return family;
  }
  return null;
}

function uaOs(ua: string): string | null {
  for (const [re, os] of UA_OS_PATTERNS) {
    if (re.test(ua)) return os;
  }
  return null;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function str(v: unknown): v is string {
  return typeof v === "string";
}

/** Extract JA4 string and H2 pseudo-header order from sigint. */
function extractSigintSignals(sigint: Record<string, unknown>): {
  ja4: string | null;
  h2Pseudo: string | null;
} {
  const h2 = isObj(sigint.h2) ? sigint.h2 : null;
  const tcp = isObj(sigint.tcp_probe) ? sigint.tcp_probe : null;
  const ja4 =
    (h2 && str(h2.ja4) ? h2.ja4 : null) ??
    (tcp && str(tcp.ja4) ? tcp.ja4 : null);
  const h2Pseudo =
    h2 && str(h2.pseudo_header_order) ? h2.pseudo_header_order : null;
  return { ja4, h2Pseudo };
}

/** Resolve browser families from JA4 cipher hash and H2 pseudo-header order. */
function resolveFamilies(
  ja4: string | null,
  h2Pseudo: string | null,
): {
  ja4Family: string | null;
  h2Family: string | null;
  cipherHash: string | null;
} {
  let ja4Family: string | null = null;
  let cipherHash: string | null = null;
  if (ja4) {
    cipherHash = parseCipherHash(ja4);
    if (cipherHash) ja4Family = CIPHER_HASH_FAMILY[cipherHash] ?? null;
  }
  const h2Family = h2Pseudo ? (H2_PSEUDO_FAMILY[h2Pseudo] ?? null) : null;
  return { ja4Family, h2Family, cipherHash };
}

// -- Individual rules --

function checkJa4UaMismatch(r: ResolvedSignals): Ja4UaSignal | null {
  if (!r.ja4Family || !r.uaBrowser || r.ja4Family === r.uaBrowser) return null;
  return {
    code: "JA4_UA_BROWSER_MISMATCH",
    severity: 0.95,
    expected: `JA4 cipher → ${r.ja4Family}`,
    actual: `UA claims ${r.uaBrowser}`,
  };
}

function checkH2UaMismatch(r: ResolvedSignals): Ja4UaSignal | null {
  if (!r.h2Family || !r.uaBrowser || r.h2Family === r.uaBrowser) return null;
  return {
    code: "H2_UA_BROWSER_MISMATCH",
    severity: 0.95,
    expected: `H2 pseudo-header order "${r.h2Pseudo}" → ${r.h2Family}`,
    actual: `UA claims ${r.uaBrowser}`,
  };
}

function checkJa4H2Mismatch(r: ResolvedSignals): Ja4UaSignal | null {
  if (!r.ja4Family || !r.h2Family || r.ja4Family === r.h2Family) return null;
  return {
    code: "JA4_H2_FAMILY_MISMATCH",
    severity: 0.9,
    expected: `JA4 → ${r.ja4Family} matches H2 → ${r.h2Family}`,
    actual: `JA4 says ${r.ja4Family}, H2 says ${r.h2Family}`,
  };
}

function checkSafariOsMismatch(r: ResolvedSignals): Ja4UaSignal | null {
  if (!r.cipherHash || !(r.cipherHash in SAFARI_OS) || !r.uaOs) return null;
  const expectedOs = SAFARI_OS[r.cipherHash];
  if (expectedOs === r.uaOs) return null;
  return {
    code: "SAFARI_OS_MISMATCH",
    severity: 0.85,
    expected: `Safari TLS cipher → ${expectedOs}`,
    actual: `UA claims ${r.uaOs}`,
  };
}

const RULES = [
  checkJa4UaMismatch,
  checkH2UaMismatch,
  checkJa4H2Mismatch,
  checkSafariOsMismatch,
];

// -- Analysis --

export function analyzeJa4Ua(
  sigint: unknown,
  userAgent: string,
): Ja4UaAnalysisResult {
  const uaBrowser = uaFamily(userAgent);
  const uaOsValue = uaOs(userAgent);

  if (!isObj(sigint)) {
    return {
      ja4_browser_family: null,
      h2_browser_family: null,
      ua_browser_family: uaBrowser,
      ua_os: uaOsValue,
      signals: [],
    };
  }

  const { ja4, h2Pseudo } = extractSigintSignals(sigint);
  const { ja4Family, h2Family, cipherHash } = resolveFamilies(ja4, h2Pseudo);

  const resolved: ResolvedSignals = {
    ja4Family,
    h2Family,
    h2Pseudo,
    cipherHash,
    uaBrowser,
    uaOs: uaOsValue,
  };
  const signals = RULES.map((rule) => rule(resolved)).filter(
    (s): s is Ja4UaSignal => s !== null,
  );

  return {
    ja4_browser_family: ja4Family,
    h2_browser_family: h2Family,
    ua_browser_family: uaBrowser,
    ua_os: uaOsValue,
    signals,
  };
}
