import { describe, it, expect, beforeEach } from "vitest";
import { analyzeBrowserEngine } from "./index";
import {
  _seedBrowserBaselinesForTesting,
  _resetBrowserBaselinesForTesting,
  type BrowserBaseline,
} from "../../services/network/browser-baselines";

const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1";
const CHROME_WIN_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
const FIREFOX_UA =
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0";

function chromeBaseline(n = 50000): BrowserBaseline {
  return {
    n_sessions: n,
    fields: {
      "engine.jsEngine": { V8: n },
      "engine.layoutEngine": { Blink: n },
      "engine.evalToStringLength": { "33": n },
      "engine.functionToStringLength": { "33": n },
      "engine.stackFormatHash": { "491e18af": n },
      "navigator.vendor": { "Google Inc.": n },
      "navigator.oscpuPresent": { false: n },
      "windowPrefixes.apple": { "0": n },
      "windowPrefixes.moz": { "0": n },
      "windowPrefixes.webkit": { "14": n },
      "css.keyCount": { "456": n },
      "navigator.propertiesLength": { "82": n },
      "headless.chromium": { true: n },
      "tls.ja4_cipher_hash": { "8daaf6152771": n },
      "tls.h2_pseudo_header_order": { "m,a,s,p": n },
      "tls.h2_protocol": { h2: n },
      "tls.cipher_count": { "17": n },
      "tls.has_grease": { true: n },
    },
  };
}

function safariIosBaseline(n = 50000): BrowserBaseline {
  return {
    n_sessions: n,
    fields: {
      "engine.jsEngine": { JavaScriptCore: n },
      "engine.layoutEngine": { WebKit: n },
      "engine.evalToStringLength": { "37": n },
      "engine.functionToStringLength": { "37": n },
      "engine.stackFormatHash": { "22ff7e4a": n },
      "navigator.vendor": { "Apple Computer, Inc.": n },
      "navigator.oscpuPresent": { false: n },
      "windowPrefixes.apple": { "4": n },
      "windowPrefixes.moz": { "0": n },
      "windowPrefixes.webkit": { "18": n },
      "css.keyCount": { "423": n },
      "navigator.propertiesLength": { "40": n },
      "headless.chromium": { false: n },
      "tls.ja4_cipher_hash": { a09f3c656075: n },
      "tls.h2_pseudo_header_order": { "m,s,a,p": n },
      "tls.h2_protocol": { h2: n },
      "tls.cipher_count": { "20": n },
      "tls.has_grease": { true: n },
    },
  };
}

function realChromeDevice() {
  return {
    engine: {
      jsEngine: "V8",
      layoutEngine: "Blink",
      evalToStringLength: 33,
      functionToStringLength: 33,
      stackFormatHash: "491e18af",
    },
    navigator: {
      vendor: "Google Inc.",
      properties: new Array(82).fill("p"),
    },
    windowPrefixes: { apple: 0, moz: 0, webkit: 14 },
    css: { keyCount: 456 },
    headless: { chromium: true },
  };
}

function realSafariDevice() {
  return {
    engine: {
      jsEngine: "JavaScriptCore",
      layoutEngine: "WebKit",
      evalToStringLength: 37,
      functionToStringLength: 37,
      stackFormatHash: "22ff7e4a",
    },
    navigator: {
      vendor: "Apple Computer, Inc.",
      properties: new Array(40).fill("p"),
    },
    windowPrefixes: { apple: 4, moz: 0, webkit: 18 },
    css: { keyCount: 423 },
    headless: { chromium: false },
  };
}

function realChromeSigint() {
  return {
    h2: {
      ja4: "t13d1517h2_8daaf6152771_5151127fa428",
      pseudo_header_order: "m,a,s,p",
      protocol: "h2",
      tls_signals: { cipher_count: 17, has_grease: true },
    },
  };
}

function realSafariSigint() {
  return {
    h2: {
      ja4: "t13d2013h2_a09f3c656075_3798386c97ff",
      pseudo_header_order: "m,s,a,p",
      protocol: "h2",
      tls_signals: { cipher_count: 20, has_grease: true },
    },
  };
}

beforeEach(() => {
  _resetBrowserBaselinesForTesting();
});

describe("analyzeBrowserEngine", () => {
  describe("happy path — claim matches engine", () => {
    it("real Chrome session against Chrome baseline → no signals", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(r.claimed_key).toBe("Chrome 147");
      expect(r.baseline_source).toBe("version");
      expect(r.signals).toHaveLength(0);
    });

    it("real iPhone Safari against Safari iOS baseline → no signals", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Safari iOS 18.7": safariIosBaseline() },
      });
      const r = analyzeBrowserEngine({
        device: realSafariDevice(),
        sigint: realSafariSigint(),
        ua: SAFARI_IOS_UA,
        secChUa: null,
        incognito: false,
      });
      expect(r.claimed_key).toBe("Safari iOS 18.7");
      expect(r.signals).toHaveLength(0);
    });
  });

  describe("hard break — engine impossibility", () => {
    it("Safari UA + V8 jsEngine → BROWSER_ENGINE_INCONSISTENT_HARD", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Safari iOS 18.7": safariIosBaseline() },
      });
      const spoofed = realSafariDevice();
      spoofed.engine.jsEngine = "V8";
      const r = analyzeBrowserEngine({
        device: spoofed,
        sigint: realSafariSigint(),
        ua: SAFARI_IOS_UA,
        secChUa: null,
        incognito: false,
      });
      const hard = r.signals.find(
        (s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD",
      );
      expect(hard).toBeDefined();
      expect(hard?.severity).toBe(0.95);
      expect(hard?.evidence).toContain("engine.jsEngine=V8");
    });

    it("Chrome UA + Apple vendor → BROWSER_ENGINE_INCONSISTENT_HARD", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const spoofed = realChromeDevice();
      spoofed.navigator.vendor = "Apple Computer, Inc.";
      const r = analyzeBrowserEngine({
        device: spoofed,
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(
        r.signals.find((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD"),
      ).toBeDefined();
    });

    it("Chrome UA + Safari JA4 cipher hash → BROWSER_ENGINE_INCONSISTENT_HARD (TLS field)", () => {
      // Cross-engine TLS fingerprint mismatch: claims Chrome but ships
      // Safari's TLS profile. Hits the TLS_FIELDS portion of the check.
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const sigintWithSafariJa4 = realChromeSigint();
      sigintWithSafariJa4.h2.ja4 = "t13d2013h2_a09f3c656075_xxxxxxxxxxxx";
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: sigintWithSafariJa4,
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      const hard = r.signals.find(
        (s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD",
      );
      expect(hard).toBeDefined();
      expect(hard?.evidence).toContain("tls.ja4_cipher_hash=a09f3c656075");
    });

    it("multiple field mismatches roll up into one signal", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const spoofed = realChromeDevice();
      spoofed.engine.jsEngine = "SpiderMonkey";
      spoofed.navigator.vendor = "";
      const r = analyzeBrowserEngine({
        device: spoofed,
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      const hard = r.signals.find(
        (s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD",
      );
      expect(hard).toBeDefined();
      expect(hard?.evidence).toContain("engine.jsEngine=SpiderMonkey");
      expect(hard?.evidence).toContain("navigator.vendor=");
    });
  });

  describe("soft signal cold-start protection", () => {
    it("does NOT fire from engine_family fallback (family aggregates legitimately-different versions)", () => {
      // Engine-family fallback aggregates multiple browser versions whose
      // invariants legitimately differ (FF 149's css.keyCount=382 vs
      // FF 150's 383). Soft signal would mis-fire on every real session.
      _seedBrowserBaselinesForTesting({
        engine_families: { chromium: chromeBaseline(60000) },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="148"', // unknown version → family fallback
        incognito: false,
      });
      expect(r.baseline_source).toBe("engine_family");
      expect(
        r.signals.find((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_SOFT"),
      ).toBeUndefined();
    });

    it("does NOT fire when baseline.n_sessions < MIN_HARD_BREAK_N", () => {
      // Sparse baseline: Laplace smoothing produces baseline-low logL
      // even for matching values. Don't fire soft on cold-start data.
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline(50) },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(
        r.signals.find((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_SOFT"),
      ).toBeUndefined();
    });
  });

  describe("per-field hard-break threshold (totalForField gates independently)", () => {
    it("does NOT hard-break a field whose population is below MIN_HARD_BREAK_N", () => {
      // JS fields well-populated (50k) but TLS fields sparse (50). A
      // never-seen TLS hash should not hard-break — too little data to
      // call it impossible. JS fields all match, so no signal at all.
      const sparseTls = chromeBaseline(50000);
      sparseTls.fields["tls.ja4_cipher_hash"] = { "8daaf6152771": 50 };
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": sparseTls },
      });
      const sigint = realChromeSigint();
      sigint.h2.ja4 = "t13d1517h2_NEVERSEENBEFORE_xxxxxxxxxxxx";
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint,
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(
        r.signals.find((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD"),
      ).toBeUndefined();
    });
  });

  describe("cold-start fallback chain", () => {
    it("missing version baseline + present engine_family → uses family fallback", () => {
      _seedBrowserBaselinesForTesting({
        browsers: {},
        engine_families: { chromium: chromeBaseline(60000) },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(r.baseline_source).toBe("engine_family");
      expect(r.signals).toHaveLength(0);
    });

    it("incognito session falls back to non-incognito version baseline", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: true,
      });
      expect(r.claimed_key).toBe("Chrome 147 incognito");
      expect(r.baseline_source).toBe("version_no_incognito");
      expect(r.signals).toHaveLength(0);
    });

    it("no baseline anywhere → no signals (cold-start safe)", () => {
      _seedBrowserBaselinesForTesting({});
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(r.baseline_source).toBe("none");
      expect(r.signals).toHaveLength(0);
    });

    it("hard break suppressed when only the engine-family fallback is small", () => {
      _seedBrowserBaselinesForTesting({
        engine_families: { chromium: chromeBaseline(500) },
      });
      const spoofed = realChromeDevice();
      spoofed.engine.jsEngine = "SpiderMonkey";
      const r = analyzeBrowserEngine({
        device: spoofed,
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Google Chrome";v="147"',
        incognito: false,
      });
      expect(
        r.signals.find((s) => s.code === "BROWSER_ENGINE_INCONSISTENT_HARD"),
      ).toBeUndefined();
    });
  });

  describe("UA parsing edge cases", () => {
    it("Brave is identified via sec-ch-ua brand even though UA says Chrome", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Brave 147": chromeBaseline() },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: CHROME_WIN_UA,
        secChUa: '"Brave";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
        incognito: false,
      });
      expect(r.claimed_key).toBe("Brave 147");
      expect(r.engine_family).toBe("chromium");
    });

    it("Firefox UA → claimed_key Firefox 149", () => {
      _seedBrowserBaselinesForTesting({});
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: FIREFOX_UA,
        secChUa: null,
        incognito: false,
      });
      expect(r.claimed_key).toBe("Firefox 149");
      expect(r.engine_family).toBe("gecko");
    });

    it("unknown UA → no signals, no claimed_key", () => {
      _seedBrowserBaselinesForTesting({
        browsers: { "Chrome 147": chromeBaseline() },
      });
      const r = analyzeBrowserEngine({
        device: realChromeDevice(),
        sigint: realChromeSigint(),
        ua: "curl/8.0",
        secChUa: null,
        incognito: false,
      });
      expect(r.claimed_key).toBeNull();
      expect(r.signals).toHaveLength(0);
    });
  });
});
