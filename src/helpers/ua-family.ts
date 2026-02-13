/**
 * User-Agent Family Parser
 *
 * Uses ua-parser-js for reliable browser detection.
 * Extracts browser family for statistical baseline grouping.
 *
 * @module helpers/ua-family
 */

import * as UAParser from "ua-parser-js";

export interface UAFamily {
  /** Browser name: 'Chrome', 'Firefox', 'Safari', 'Edge', etc. */
  browser: string;
  /** Major version number, or null if not detected */
  majorVersion: number | null;
  /** OS name: 'Windows', 'macOS', 'Linux', 'iOS', 'Android', etc. */
  os: string;
  /** Device type: 'mobile', 'tablet', 'desktop', etc. */
  deviceType: string;
  /** Normalized key for baseline grouping (lowercase browser name) */
  baselineKey: string;
}

/**
 * Bot patterns - these get their own baseline category.
 * ua-parser-js doesn't always catch these.
 */
const BOT_PATTERNS = [
  /bot/i,
  /crawler/i,
  /spider/i,
  /scraper/i,
  /\bcurl\b/i,
  /\bwget\b/i,
  /python-requests/i,
  /python-urllib/i,
  /java\//i,
  /go-http-client/i,
  /node-fetch/i,
  /axios/i,
  /httpx/i,
  /okhttp/i,
  /libwww/i,
  /headless/i,
  /phantom/i,
  /selenium/i,
  /puppeteer/i,
  /playwright/i,
];

/** Substring-match rules: if the lowercased name includes the key, return the value. */
const BROWSER_INCLUDES: [string, string][] = [
  ["chromium", "chrome"],
  ["chrome webview", "chrome"],
  ["chrome headless", "chrome"],
  ["edge", "edge"],
  ["firefox", "firefox"],
  ["opera", "opera"],
];

/** Exact-match rules: lowercased name must equal the key. */
const BROWSER_EXACT: Record<string, string> = {
  safari: "safari",
  "mobile safari": "safari",
  ie: "ie",
  "internet explorer": "ie",
  // Webview apps
  instagram: "instagram",
  gemini: "gemini",
  signal: "signal",
  slack: "slack",
  duckduckgo: "duckduckgo",
  google: "google_app",
  snapchat: "snapchat",
  pinterest: "pinterest",
};

/** Normalize browser name for consistent baseline keys. */
export function normalizeBrowserName(browser: string | undefined): string {
  if (!browser) return "unknown";
  const lower = browser.toLowerCase();
  if (BROWSER_EXACT[lower]) return BROWSER_EXACT[lower];
  for (const [substr, key] of BROWSER_INCLUDES) {
    if (lower.includes(substr)) return key;
  }
  return lower.replace(/\s+/g, "_");
}

/**
 * Parse User-Agent string into browser family.
 *
 * @param userAgent - Full User-Agent string
 * @returns Parsed UA family info
 *
 * @example
 * parseUAFamily("Mozilla/5.0 ... Chrome/144.0.0.0 Safari/537.36")
 * // { browser: 'Chrome', majorVersion: 144, os: 'Windows', deviceType: 'desktop', baselineKey: 'chrome' }
 */
export function parseUAFamily(userAgent: string | null | undefined): UAFamily {
  const unknown: UAFamily = {
    browser: "unknown",
    majorVersion: null,
    os: "unknown",
    deviceType: "unknown",
    baselineKey: "unknown",
  };

  if (!userAgent) {
    return unknown;
  }

  // Check for bots first (ua-parser-js doesn't always catch these)
  for (const pattern of BOT_PATTERNS) {
    if (pattern.test(userAgent)) {
      return {
        browser: "bot",
        majorVersion: null,
        os: "unknown",
        deviceType: "bot",
        baselineKey: "bot",
      };
    }
  }

  // Use ua-parser-js for reliable parsing
  const parser = new UAParser.UAParser(userAgent);
  const result = parser.getResult();

  const browser = result.browser.name || "unknown";
  const majorVersion = result.browser.major
    ? parseInt(result.browser.major, 10)
    : null;
  const os = result.os.name || "unknown";
  const deviceType = result.device.type || "desktop"; // ua-parser returns undefined for desktop

  return {
    browser,
    majorVersion: Number.isNaN(majorVersion) ? null : majorVersion,
    os,
    deviceType,
    baselineKey: normalizeBrowserName(browser),
  };
}

/**
 * Get baseline grouping key for a User-Agent.
 *
 * This is the key used for statistical baseline storage.
 * Groups by browser family only, not version.
 *
 * @param userAgent - Full User-Agent string
 * @returns Baseline key (e.g., 'chrome', 'firefox', 'safari')
 */
export function getBaselineKey(userAgent: string | null | undefined): string {
  return parseUAFamily(userAgent).baselineKey;
}

/**
 * Get detailed UA info for logging/debugging.
 *
 * @param userAgent - Full User-Agent string
 * @returns Formatted string with browser, version, and OS
 */
export function getUADescription(userAgent: string | null | undefined): string {
  const ua = parseUAFamily(userAgent);
  if (ua.baselineKey === "unknown" || ua.baselineKey === "bot") {
    return ua.baselineKey;
  }
  const version = ua.majorVersion ? ` ${ua.majorVersion}` : "";
  const os = ua.os !== "unknown" ? ` on ${ua.os}` : "";
  return `${ua.browser}${version}${os}`;
}
