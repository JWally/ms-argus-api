/**
 * User-Agent Family Parser
 *
 * Uses ua-parser-js for reliable browser detection.
 * Extracts browser family for statistical baseline grouping.
 *
 * @module helpers/ua-family
 */

import UAParser = require("ua-parser-js");

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

/**
 * Normalize browser name for consistent baseline keys.
 * Groups Chromium variants together, handles edge cases.
 */
function normalizeBrowserName(browser: string | undefined): string {
  if (!browser) return "unknown";

  const lower = browser.toLowerCase();

  // Group Chromium-based browsers
  if (
    lower.includes("chromium") ||
    lower === "chrome webview" ||
    lower === "chrome headless"
  ) {
    return "chrome";
  }

  // Group Edge variants
  if (lower.includes("edge")) {
    return "edge";
  }

  // Group Firefox variants
  if (lower.includes("firefox")) {
    return "firefox";
  }

  // Group Safari variants (but not Chrome which contains Safari in UA)
  if (lower === "safari" || lower === "mobile safari") {
    return "safari";
  }

  // Group Opera variants
  if (lower.includes("opera")) {
    return "opera";
  }

  // IE variants
  if (lower === "ie" || lower === "internet explorer") {
    return "ie";
  }

  // Return as-is for others (Samsung Browser, UC Browser, etc.)
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
