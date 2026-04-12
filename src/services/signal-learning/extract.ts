/**
 * Signal Extraction
 *
 * Extracts engine-stable signal hashes from an integrity payload
 * for population-based baseline learning.
 *
 * @module services/signal-learning/extract
 */

import {
  resolveBrowserIdentity,
  type BrowserIdentity,
} from "../../helpers/browser-identity";

export interface SignalObservation {
  browserKey: string;
  signals: Array<{ module: string; hash: string }>;
  identity: BrowserIdentity;
}

/** Chromium-based browsers that share V8/Blink engine-stable signals with Chrome. */
const CHROMIUM_KEYS = new Set([
  "chrome",
  "edge",
  "opera",
  "samsung_internet",
  "vivaldi",
  "brave",
  "yandex",
]);

/**
 * Resolve the engine-level grouping key for baseline learning.
 * Webview apps are normalized to their underlying engine since the
 * engine-stable signals (math, CSS key count, etc.) are identical.
 */
export function resolveEngineKey(identity: BrowserIdentity): {
  engineKey: string;
  engineVersion: string | null;
} {
  // iOS: everything is WKWebView (JSC) — group by Safari/iOS version
  if (identity.os === "iOS") {
    const iosVersion = identity.osVersion?.split(".")[0] ?? null;
    return { engineKey: "safari", engineVersion: iosVersion };
  }

  // Android webviews: Chrome WebView (V8) — group by Chrome version
  if (identity.isWebview && identity.os === "Android") {
    // WebView UA often includes Chrome version; use it if available
    const chromeVersion = identity.browserVersion?.split(".")[0] ?? null;
    return { engineKey: "chrome", engineVersion: chromeVersion };
  }

  // Chromium family: Edge, Opera, Samsung Internet, etc. all share V8/Blink
  // and produce identical engine-stable signals as Chrome.
  if (CHROMIUM_KEYS.has(identity.baselineKey)) {
    return {
      engineKey: "chrome",
      engineVersion: identity.browserVersion?.split(".")[0] ?? null,
    };
  }

  // Non-webview, non-Chromium: use the browser's own identity
  return {
    engineKey: identity.baselineKey,
    engineVersion: identity.browserVersion?.split(".")[0] ?? null,
  };
}

/** Signal modules to extract from the device payload. */
const EXTRACTORS: Array<{
  module: string;
  extract: (device: Record<string, unknown>) => string | null;
}> = [
  {
    module: "math",
    extract: (d) => {
      const math = d.math as Record<string, unknown> | undefined;
      return typeof math?.hash === "string" ? math.hash : null;
    },
  },
  {
    module: "eval_length",
    extract: (d) => {
      const engine = d.engine as Record<string, unknown> | undefined;
      return typeof engine?.evalToStringLength === "number"
        ? String(engine.evalToStringLength)
        : null;
    },
  },
  {
    module: "css_key_count",
    extract: (d) => {
      const css = d.css as Record<string, unknown> | undefined;
      return typeof css?.keyCount === "number" ? String(css.keyCount) : null;
    },
  },
  {
    module: "window_moz",
    extract: (d) => {
      const wp = d.windowPrefixes as Record<string, unknown> | undefined;
      return typeof wp?.moz === "number" ? String(wp.moz) : null;
    },
  },
  {
    module: "worker_nav_props",
    extract: (d) => {
      const ws = d.workerScope as Record<string, unknown> | undefined;
      if (!ws) return null;
      // Try shared worker first, then dedicated
      const scopes = ws.scopes as Record<string, unknown> | undefined;
      if (scopes) {
        for (const key of ["shared", "web"]) {
          const scope = scopes[key] as Record<string, unknown> | undefined;
          if (typeof scope?.navigatorPropertyCount === "number") {
            return String(scope.navigatorPropertyCount);
          }
        }
      }
      // Legacy fallback: top-level workerScope
      if (typeof ws.navigatorPropertyCount === "number") {
        return String(ws.navigatorPropertyCount);
      }
      return null;
    },
  },
];

/**
 * Extract signal hashes from an integrity payload for baseline learning.
 *
 * Returns null if the browser can't be identified (unknown baselineKey,
 * no parseable major version).
 */
export function extractSignalObservation(
  device: unknown,
  sigint?: unknown,
): SignalObservation | null {
  const identity = resolveBrowserIdentity(device, sigint);

  if (identity.baselineKey === "unknown" || identity.baselineKey === "bot") {
    return null;
  }

  // Normalize webview apps to their underlying engine for baseline grouping.
  // On iOS, all apps use WKWebView (JSC) — group as safari-{ios_version}.
  // On Android, all apps use Chrome WebView (V8) — group as chrome-{chrome_version}.
  // This prevents hundreds of app-specific groups that never reach lock threshold.
  const { engineKey, engineVersion } = resolveEngineKey(identity);
  if (!engineVersion) return null;

  const browserKey = `${engineKey}-${engineVersion}`;
  const dev =
    device !== null && typeof device === "object"
      ? (device as Record<string, unknown>)
      : {};

  const signals: Array<{ module: string; hash: string }> = [];
  for (const { module, extract } of EXTRACTORS) {
    const hash = extract(dev);
    if (hash !== null) signals.push({ module, hash });
  }

  if (signals.length === 0) return null;

  return { browserKey, signals, identity };
}
