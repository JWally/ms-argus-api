/**
 * Unified Browser Identity Resolution
 *
 * Aggregates all available signals (UA string, worker scope, incognito detector,
 * ua-parser-js) into a single BrowserIdentity object. Handles webview apps
 * (Instagram, Gemini, Signal, Slack, etc.) that ua-parser-js returns as "WebKit".
 *
 * @module helpers/browser-identity
 */

import * as UAParser from "ua-parser-js";
import { normalizeBrowserName } from "./ua-family";

export interface BrowserIdentity {
  /** Browser name from ua-parser-js, with webview overrides applied */
  browser: string;
  /** Browser version string, or null if not detected */
  browserVersion: string | null;
  /** OS name: "iOS", "macOS", "Windows", "Android", "Linux", "Chrome OS" */
  os: string;
  /** OS version string, or null if not detected */
  osVersion: string | null;
  /** Device type: "mobile", "tablet", "desktop" */
  deviceType: string;
  /** Device model: "iPhone", "Pixel 7", etc., or null */
  deviceModel: string | null;
  /** Rendering engine: "WebKit", "Blink", "Gecko" */
  engine: string;

  /** Normalized key for baseline grouping (lowercase) */
  baselineKey: string;
  /** True if running inside an app webview (Instagram, Gemini, etc.) */
  isWebview: boolean;
  /** App name if webview, null otherwise */
  app: string | null;
  /** True if CriOS/FxiOS/EdgiOS — real browser UI on iOS using Apple TLS */
  isIosBrowser: boolean;
  /** True if incognito/private browsing detected */
  isPrivate: boolean;

  /** Worker scope JS engine: "JavaScriptCore", "V8", "SpiderMonkey", or null */
  workerEngine: string | null;
  /** Worker scope platform string, or null */
  workerPlatform: string | null;
  /** Worker scope UA version string, or null */
  workerUaVersion: string | null;

  /** Raw ua-parser-js result for consumers who want full detail */
  raw: UAParser.IResult;
}

/**
 * Webview app patterns to match in UA string when ua-parser-js returns
 * a generic browser name like "WebKit" or "Mobile Safari".
 * Each entry: [regex, app display name].
 */
const WEBVIEW_PATTERNS: [RegExp, string][] = [
  [/Instagram[\s/]?([\d.]*)/i, "Instagram"],
  [/FBAN|FBAV/i, "Facebook"],
  [/GeminiiOS\/([\d.]+)/i, "Gemini"],
  [/Signal\/([\d.]+)/i, "Signal"],
  [/Slack\/([\d.]+)/i, "Slack"],
  [/DuckDuckGo\/([\d.]+)/i, "DuckDuckGo"],
  [/GSA\/([\d.]+)/i, "Google"],
  [/Snapchat/i, "Snapchat"],
  [/Pinterest/i, "Pinterest"],
];

/** iOS alternate-browser UA tokens that use Apple's TLS stack */
const IOS_BROWSER_RE = /\b(CriOS|FxiOS|EdgiOS)\b/;

/** Browser names that trigger webview pattern matching (ua-parser-js couldn't identify) */
const GENERIC_BROWSERS = new Set(["WebKit", "Mobile Safari", "unknown"]);

/** Browser names from ua-parser-js that are known webview apps (already identified correctly) */
const KNOWN_WEBVIEW_APPS = new Set([
  "Instagram",
  "Facebook",
  "Snapchat",
  "Pinterest",
  "DuckDuckGo",
  "GSA",
  "Slack",
  "Signal",
]);

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function str(v: unknown): v is string {
  return typeof v === "string";
}

/** Get the UA string from a specific scope entry, or null. */
function scopeUA(scopes: Record<string, unknown>, name: string): string | null {
  const scope = scopes[name];
  return isObj(scope) && str(scope.userAgent) ? scope.userAgent : null;
}

/** Extract the best available UA string from the payload. */
function extractUA(device: Record<string, unknown>): string | null {
  const ws = device.workerScope;
  if (isObj(ws) && isObj(ws.scopes)) {
    const scopes = ws.scopes as Record<string, unknown>;
    return (
      scopeUA(scopes, "shared") ??
      scopeUA(scopes, "web") ??
      scopeUA(scopes, "main") ??
      null
    );
  }
  const nav = device.navigator;
  return isObj(nav) && str(nav.userAgent) ? nav.userAgent : null;
}

/** Try to match webview app patterns against the UA string. */
function detectWebviewApp(
  ua: string,
): { app: string; version: string | null } | null {
  for (const [pattern, app] of WEBVIEW_PATTERNS) {
    const match = ua.match(pattern);
    if (match) return { app, version: match[1] || null };
  }
  return null;
}

/** Extract worker scope fields from the device payload. */
function extractWorkerFields(device: Record<string, unknown>): {
  workerEngine: string | null;
  workerPlatform: string | null;
  workerUaVersion: string | null;
} {
  const ws = device.workerScope;
  if (!isObj(ws)) {
    return { workerEngine: null, workerPlatform: null, workerUaVersion: null };
  }
  return {
    workerEngine: str(ws.userAgentEngine) ? ws.userAgentEngine : null,
    workerPlatform: str(ws.platform) ? ws.platform : null,
    workerUaVersion: str(ws.userAgentVersion) ? ws.userAgentVersion : null,
  };
}

/** Resolve webview app from ua-parser-js result or UA string regex fallback. */
function resolveWebviewApp(
  ua: string | null,
  browser: string,
  browserVersion: string | null,
): { browser: string; browserVersion: string | null; app: string | null } {
  // ua-parser-js already identified a known webview app
  if (KNOWN_WEBVIEW_APPS.has(browser)) {
    return { browser, browserVersion, app: browser };
  }
  // Generic name — try regex patterns against UA string
  if (!ua || !GENERIC_BROWSERS.has(browser)) {
    return { browser, browserVersion, app: null };
  }
  const result = detectWebviewApp(ua);
  if (!result) return { browser, browserVersion, app: null };
  return {
    browser: result.app,
    browserVersion: result.version ?? browserVersion,
    app: result.app,
  };
}

/** Extract base fields from ua-parser-js result with fallback defaults. */
function extractParsedFields(result: UAParser.IResult): {
  os: string;
  osVersion: string | null;
  deviceType: string;
  deviceModel: string | null;
  engine: string;
} {
  return {
    os: result.os.name || "unknown",
    osVersion: result.os.version || null,
    deviceType: result.device.type || "desktop",
    deviceModel: result.device.model || null,
    engine: result.engine.name || "unknown",
  };
}

/** Extract isPrivate from device incognito field. */
function extractIsPrivate(device: Record<string, unknown>): boolean {
  return isObj(device.incognito) && device.incognito.isPrivate === true;
}

/**
 * Resolve a unified browser identity from all available signals.
 *
 * @param device - Raw device payload (duck-typed)
 * @param _sigint - Optional sigint payload (reserved for future use)
 * @returns Fully resolved BrowserIdentity
 */
export function resolveBrowserIdentity(
  device: unknown,
  _sigint?: unknown,
): BrowserIdentity {
  const dev = isObj(device) ? device : {};
  const ua = extractUA(dev);
  const result = new UAParser.UAParser(ua || "").getResult();

  const webview = resolveWebviewApp(
    ua,
    result.browser.name || "unknown",
    result.browser.version || null,
  );
  const parsed = extractParsedFields(result);

  return {
    browser: webview.browser,
    browserVersion: webview.browserVersion,
    ...parsed,
    baselineKey: normalizeBrowserName(webview.browser),
    isWebview: webview.app !== null,
    app: webview.app,
    isIosBrowser: ua !== null && IOS_BROWSER_RE.test(ua),
    isPrivate: extractIsPrivate(dev),
    ...extractWorkerFields(dev),
    raw: result,
  };
}
