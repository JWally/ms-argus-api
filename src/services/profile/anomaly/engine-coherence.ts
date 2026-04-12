/**
 * Engine Coherence Detector
 *
 * Cross-validates client-reported JavaScript engine identity against
 * server-side TLS ground truth. Engine identity (V8, SpiderMonkey, JSC)
 * is determined at the C++ level and cannot be spoofed from JavaScript —
 * making it the strongest signal for detecting browser identity fraud.
 *
 * Catches: Camoufox (SpiderMonkey claiming Chrome), anti-detect browsers
 * with mismatched engine/UA, headless browsers with software renderers.
 *
 * @module services/profile/anomaly/engine-coherence
 */

import type { Fingerprint } from "../../../types";
import { AnomalySignal, AnomalyCodes, createSignal } from "./types";
import {
  resolveBrowserIdentity,
  type BrowserIdentity,
} from "../../../helpers/browser-identity";
import { TLS_STACKS, STACK_H2_FAMILY, parseJa4 } from "./tls-maps";

// ---------------------------------------------------------------------------
// Reference tables (static, deterministic)
// ---------------------------------------------------------------------------

/** JS engine → browser family. */
export const ENGINE_FAMILY: Record<string, string> = {
  V8: "chromium",
  SpiderMonkey: "firefox",
  JavaScriptCore: "apple",
};

/** Layout engine → browser family. Reserved for future coherence checks. */
// Prefixed with _ so no-unused-vars ignores it; not exported so knip ignores it.
const _LAYOUT_FAMILY: Record<string, string> = {
  Blink: "chromium",
  Gecko: "firefox",
  WebKit: "apple",
};
void _LAYOUT_FAMILY;

/**
 * Valid (jsEngine, layoutEngine) combinations.
 * V8+WebKit: Brave removes window.chrome, layout detection falls to WebKit.
 * SpiderMonkey+WebKit: Modern Firefox (148+) removed MozAppearance from
 *   div.style; if the Gecko fallback checks also fail, layout detection
 *   sees webkitAppearance (which Firefox supports as an alias) + no
 *   window.chrome → "WebKit". Client-side fix deployed but older bundles
 *   may still report this combo.
 */
export const VALID_ENGINE_COMBOS = new Set([
  "V8:Blink",
  "V8:WebKit",
  "SpiderMonkey:Gecko",
  "SpiderMonkey:WebKit",
  "JavaScriptCore:WebKit",
]);

/** navigator.vendor → browser family. */
export const VENDOR_FAMILY: Record<string, string> = {
  "Google Inc.": "chromium",
  "": "firefox",
  "Apple Computer, Inc.": "apple",
};

// Math hash-to-engine mapping removed — replaced by population-based
// signal baseline learning in signal-baseline-detector.ts.
// The baseline system learns valid hashes from real traffic instead of
// relying on hardcoded maps that need manual updates.

/** Known software renderers indicating headless/VM environments. */
const SOFTWARE_RENDERER =
  /SwiftShader|llvmpipe|Mesa DRI|VMware SVGA|Microsoft Basic Render Driver/i;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object";
}

function push(arr: AnomalySignal[], signal: AnomalySignal | null): void {
  if (signal) arr.push(signal);
}

/** Resolve TLS browser family from the fingerprint's JA4 string. */
function resolveTlsFamily(fingerprint: Fingerprint): string | null {
  if (!fingerprint.ja4) return null;
  const parsed = parseJa4(fingerprint.ja4);
  if (!parsed) return null;
  const stack = TLS_STACKS[parsed.cipherHash];
  return stack ? (STACK_H2_FAMILY[stack.stack] ?? null) : null;
}

/** Extract a nested string field via duck-typing. */
function str(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === "string" ? v : undefined;
}

/** Extract WebGL renderer from worker scopes (try shared → web → main). */
function extractWorkerWebglRenderer(
  device: Record<string, unknown>,
): string | undefined {
  const ws = device.workerScope;
  if (!isObj(ws)) return undefined;

  const scopes = ws.scopes;
  if (!isObj(scopes))
    return str(ws as Record<string, unknown>, "webglRenderer");

  for (const key of ["shared", "web", "main"]) {
    const scope = scopes[key];
    if (isObj(scope)) {
      const renderer = str(scope as Record<string, unknown>, "webglRenderer");
      if (renderer) return renderer;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/**
 * RARE_ENGINE_COMBO: jsEngine + layoutEngine must be a valid combination.
 * V8+Gecko or SpiderMonkey+Blink are physically impossible.
 */
function checkEngineCombination(
  engine: Record<string, unknown>,
): AnomalySignal | null {
  const jsEngine = str(engine, "jsEngine");
  const layoutEngine = str(engine, "layoutEngine");

  if (!jsEngine || !layoutEngine) return null;
  if (jsEngine === "unknown" || layoutEngine === "unknown") return null;

  const combo = `${jsEngine}:${layoutEngine}`;
  if (VALID_ENGINE_COMBOS.has(combo)) return null;

  return createSignal("STATISTICAL", AnomalyCodes.RARE_ENGINE_COMBO, 0.9, {
    expected: `valid engine pair (${[...VALID_ENGINE_COMBOS].join(", ")})`,
    actual: `${jsEngine} + ${layoutEngine} — impossible combination`,
    fields: ["device.engine.jsEngine", "device.engine.layoutEngine"],
  });
}

/**
 * RARE_ENGINE_FOR_UA: JS engine must match the TLS-derived browser family.
 * SpiderMonkey (Firefox engine) + BoringSSL (Chrome TLS) = Camoufox.
 */
function checkEngineForUa(
  engine: Record<string, unknown>,
  _identity: BrowserIdentity,
  tlsFamily: string | null,
): AnomalySignal | null {
  if (!tlsFamily) return null;
  const jsEngine = str(engine, "jsEngine");
  if (!jsEngine || jsEngine === "unknown") return null;

  const engineFamily = ENGINE_FAMILY[jsEngine];
  if (!engineFamily) return null;
  if (engineFamily === tlsFamily) return null;

  return createSignal("STATISTICAL", AnomalyCodes.RARE_ENGINE_FOR_UA, 0.95, {
    expected: `jsEngine ${jsEngine} (${engineFamily}) matches TLS family`,
    actual: `TLS is ${tlsFamily} — engine/TLS mismatch`,
    fields: ["device.engine.jsEngine", "fingerprint.ja4"],
  });
}

/**
 * RARE_MATHS_FOR_UA: Flags math function tampering (fingerprint randomizers).
 *
 * Hash-vs-population comparison is now handled by signal-baseline-detector.ts
 * which learns valid hashes from real traffic.
 */
function checkMathTampering(
  mathModule: Record<string, unknown>,
): AnomalySignal | null {
  if (mathModule.lied === true) {
    return createSignal("STATISTICAL", AnomalyCodes.RARE_MATHS_FOR_UA, 0.8, {
      expected: "math functions return consistent results",
      actual: "math functions tampered (results differ between calls)",
      fields: ["device.math.lied"],
    });
  }
  return null;
}

/**
 * RARE_VENDOR_FOR_UA: navigator.vendor must match TLS-derived browser family.
 * "Google Inc." + NSS (Firefox TLS) = spoofed vendor.
 */
function checkVendorForUa(
  nav: Record<string, unknown>,
  identity: BrowserIdentity,
  tlsFamily: string | null,
): AnomalySignal | null {
  if (!tlsFamily) return null;
  // On iOS all browsers report Apple vendor + SecureTransport — always consistent
  if (identity.os === "iOS") return null;

  const vendor = nav.vendor;
  // vendor must be a string (including empty string for Firefox)
  if (typeof vendor !== "string") return null;

  const vendorFamily = VENDOR_FAMILY[vendor];
  if (!vendorFamily) return null; // unknown vendor value, don't flag
  if (vendorFamily === tlsFamily) return null;

  return createSignal("STATISTICAL", AnomalyCodes.RARE_VENDOR_FOR_UA, 0.85, {
    expected: `vendor "${vendor}" (${vendorFamily}) matches TLS family`,
    actual: `TLS is ${tlsFamily} — vendor/TLS mismatch`,
    fields: ["device.navigator.vendor", "fingerprint.ja4"],
  });
}

/**
 * RARE_WEBGL_VENDOR_FOR_UA: Software renderer on desktop = likely headless.
 * Suppressed on mobile where low-end devices may legitimately use software renderers.
 */
function checkWebglForUa(
  device: Record<string, unknown>,
  identity: BrowserIdentity,
): AnomalySignal | null {
  if (identity.deviceType !== "desktop") return null;

  const renderer = extractWorkerWebglRenderer(device);
  if (!renderer) return null;
  if (!SOFTWARE_RENDERER.test(renderer)) return null;

  return createSignal(
    "STATISTICAL",
    AnomalyCodes.RARE_WEBGL_VENDOR_FOR_UA,
    0.7,
    {
      expected: "hardware GPU renderer on desktop",
      actual: `software renderer: ${renderer}`,
      fields: ["device.workerScope.webglRenderer"],
    },
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Detect engine coherence anomalies.
 *
 * Cross-validates client-reported JS engine, layout engine, navigator.vendor,
 * math precision, and WebGL renderer against server-side TLS ground truth.
 */
export function detectEngineCoherence(
  fingerprint: Fingerprint,
  raw?: unknown,
  sigint?: unknown,
): AnomalySignal[] {
  const signals: AnomalySignal[] = [];

  const device = isObj(raw) ? raw : {};
  const engine = isObj(device.engine)
    ? (device.engine as Record<string, unknown>)
    : {};
  const nav = isObj(device.navigator)
    ? (device.navigator as Record<string, unknown>)
    : {};
  const mathModule = isObj(device.math)
    ? (device.math as Record<string, unknown>)
    : {};

  const identity = resolveBrowserIdentity(raw, sigint);
  const tlsFamily = resolveTlsFamily(fingerprint);

  push(signals, checkEngineCombination(engine));
  push(signals, checkEngineForUa(engine, identity, tlsFamily));
  push(signals, checkMathTampering(mathModule));
  push(signals, checkVendorForUa(nav, identity, tlsFamily));
  push(signals, checkWebglForUa(device, identity));

  return signals;
}
