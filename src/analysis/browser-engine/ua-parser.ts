/**
 * Coarse UA → (browser, version, engine_family) parser shared by the
 * baseline builder and the runtime analyzer. Both consumers MUST use this
 * single implementation — drift between them would mean the analyzer's
 * lookup keys don't match the builder's histogram keys.
 */

export interface ParsedBrowser {
  browser: string;
  version: string;
  engineFamily: string;
}

interface UaRule {
  /** Regex over the UA. */
  match: RegExp;
  /** Browser display name. */
  browser: string;
  /** Engine family for fallback lookup. */
  engineFamily: string;
  /** Capture-group index that holds the version (default 1). */
  versionGroup?: number;
}

/** Order matters — first match wins. Edge before Chrome (UA contains both). */
const RULES: UaRule[] = [
  // Edge / EdgeOnIos / EdgeAndroid — Edg / EdgeA / EdgiOS token.
  {
    match: /Edg(?:e|A|iOS)?\/(\d+)/,
    browser: "Edge",
    engineFamily: "chromium",
  },
  // Firefox iOS uses Safari engine.
  { match: /FxiOS\/(\d+)/, browser: "Firefox iOS", engineFamily: "webkit" },
  // Firefox proper (Gecko).
  { match: /Firefox\/(\d+)/, browser: "Firefox", engineFamily: "gecko" },
  // Chrome iOS uses Safari engine (CriOS).
  { match: /CriOS\/(\d+)/, browser: "Chrome iOS", engineFamily: "webkit" },
  // Chrome on desktop / Android. Must be checked AFTER Edge / FxiOS / CriOS.
  { match: /Chrome\/(\d+)/, browser: "Chrome", engineFamily: "chromium" },
];

/** Safari has its own resolver because version comes from `Version/N`, not the
 *  Safari/N segment, and OS distinguishes iOS vs macOS. */
function parseSafari(ua: string): ParsedBrowser | null {
  if (/iPhone|iPad|iPod/.test(ua)) {
    const v = ua.match(/Version\/(\d+(?:\.\d+)?)/);
    return {
      browser: "Safari iOS",
      version: v?.[1] ?? "?",
      engineFamily: "webkit",
    };
  }
  if (/Macintosh.*Safari/.test(ua)) {
    const v = ua.match(/Version\/(\d+(?:\.\d+)?)/);
    return {
      browser: "Safari macOS",
      version: v?.[1] ?? "?",
      engineFamily: "webkit",
    };
  }
  return null;
}

function parseBrave(secChUa: string | null): ParsedBrowser | null {
  if (!secChUa || !/"Brave"/.test(secChUa)) return null;
  const m = secChUa.match(/"Brave";v="(\d+)"/);
  return {
    browser: "Brave",
    version: m?.[1] ?? "?",
    engineFamily: "chromium",
  };
}

export function parseUaToBrowser(
  ua: string | null,
  secChUa: string | null,
): ParsedBrowser | null {
  if (!ua) return null;

  // Brave hides itself in UA (claims Chrome) and only surfaces via
  // sec-ch-ua brand list. Check first so we don't misclassify as Chrome.
  const brave = parseBrave(secChUa);
  if (brave) return brave;

  for (const rule of RULES) {
    const m = ua.match(rule.match);
    if (m) {
      return {
        browser: rule.browser,
        version: m[rule.versionGroup ?? 1],
        engineFamily: rule.engineFamily,
      };
    }
  }

  return parseSafari(ua);
}
