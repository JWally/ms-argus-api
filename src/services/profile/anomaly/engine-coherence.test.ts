import { describe, it, expect } from "vitest";
import { detectEngineCoherence } from "./engine-coherence";
import type { Fingerprint } from "../../../types";

// -- UA strings -----------------------------------------------------------

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
const FIREFOX_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
const SAFARI_MAC_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const BRAVE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

// -- Helpers --------------------------------------------------------------

function fp(overrides: Partial<Fingerprint>): Fingerprint {
  return overrides as Fingerprint;
}

// Test helper: positional args match the fixture-building idiom used throughout
// this file's describe blocks. `device(ua, engine, nav, math, workerScope)`.
// eslint-disable-next-line max-params
function device(
  ua: string,
  engine?: { jsEngine?: string; layoutEngine?: string },
  nav?: Record<string, unknown>,
  math?: Record<string, unknown>,
  workerScope?: Record<string, unknown>,
): Record<string, unknown> {
  return {
    navigator: { userAgent: ua, ...nav },
    engine: engine ?? {},
    math: math ?? {},
    workerScope: workerScope ?? {},
  };
}

/** BoringSSL JA4 (Chromium) */
const JA4_BORINGSSL = "t13d1516h2_8daaf6152771_e5627efa2ab1";
/** NSS JA4 (Firefox) */
const JA4_NSS = "t13d1516h2_5b57614c22b0_e5627efa2ab1";
/** Secure Transport JA4 (Apple) */
const JA4_SECTRANS = "t13d1516h2_a09f3c656075_e5627efa2ab1";

function hasCode(signals: { code: string }[], code: string): boolean {
  return signals.some((s) => s.code === code);
}

// -- Tests ----------------------------------------------------------------

describe("detectEngineCoherence", () => {
  // ---- Coherent payloads (no signals) -----------------------------------

  describe("coherent payloads produce no signals", () => {
    it("Chrome: V8 + Blink + BoringSSL + Google vendor", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          { vendor: "Google Inc." },
        ),
      );
      expect(signals).toEqual([]);
    });

    it("Firefox: SpiderMonkey + Gecko + NSS + empty vendor", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_NSS }),
        device(
          FIREFOX_UA,
          { jsEngine: "SpiderMonkey", layoutEngine: "Gecko" },
          { vendor: "" },
        ),
      );
      expect(signals).toEqual([]);
    });

    it("Safari macOS: JSC + WebKit + SecureTransport + Apple vendor", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_SECTRANS }),
        device(
          SAFARI_MAC_UA,
          { jsEngine: "JavaScriptCore", layoutEngine: "WebKit" },
          { vendor: "Apple Computer, Inc." },
        ),
      );
      expect(signals).toEqual([]);
    });

    it("Safari iOS: JSC + WebKit + SecureTransport", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_SECTRANS }),
        device(
          SAFARI_IOS_UA,
          { jsEngine: "JavaScriptCore", layoutEngine: "WebKit" },
          { vendor: "Apple Computer, Inc." },
        ),
      );
      expect(signals).toEqual([]);
    });
  });

  // ---- RARE_ENGINE_COMBO ------------------------------------------------

  describe("RARE_ENGINE_COMBO", () => {
    it("V8 + Gecko is impossible → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "V8", layoutEngine: "Gecko" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_COMBO")).toBe(true);
    });

    it("SpiderMonkey + Blink is impossible → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_NSS }),
        device(FIREFOX_UA, { jsEngine: "SpiderMonkey", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_COMBO")).toBe(true);
    });

    it("V8 + WebKit is valid (Brave) → no signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(BRAVE_UA, { jsEngine: "V8", layoutEngine: "WebKit" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_COMBO")).toBe(false);
    });

    it("unknown engines are not flagged", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "unknown", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_COMBO")).toBe(false);
    });
  });

  // ---- RARE_ENGINE_FOR_UA -----------------------------------------------

  describe("RARE_ENGINE_FOR_UA", () => {
    it("Camoufox: SpiderMonkey + BoringSSL TLS → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "SpiderMonkey", layoutEngine: "Gecko" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_FOR_UA")).toBe(true);
      const sig = signals.find((s) => s.code === "RARE_ENGINE_FOR_UA")!;
      expect(sig.severity).toBe(0.95);
    });

    it("V8 + NSS (Firefox TLS) → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_NSS }),
        device(FIREFOX_UA, { jsEngine: "V8", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_FOR_UA")).toBe(true);
    });

    it("no signal when jsEngine is unknown", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "unknown", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_FOR_UA")).toBe(false);
    });

    it("no signal when JA4 is missing", () => {
      const signals = detectEngineCoherence(
        fp({}),
        device(CHROME_UA, { jsEngine: "V8", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_ENGINE_FOR_UA")).toBe(false);
    });
  });

  // ---- RARE_VENDOR_FOR_UA -----------------------------------------------

  describe("RARE_VENDOR_FOR_UA", () => {
    it("Google vendor + NSS TLS → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_NSS }),
        device(
          FIREFOX_UA,
          { jsEngine: "SpiderMonkey", layoutEngine: "Gecko" },
          { vendor: "Google Inc." },
        ),
      );
      expect(hasCode(signals, "RARE_VENDOR_FOR_UA")).toBe(true);
    });

    it("empty vendor + BoringSSL TLS → signal (Firefox vendor on Chromium TLS)", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          { vendor: "" },
        ),
      );
      expect(hasCode(signals, "RARE_VENDOR_FOR_UA")).toBe(true);
    });

    it("no signal when vendor is undefined", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "V8", layoutEngine: "Blink" }, {}),
      );
      expect(hasCode(signals, "RARE_VENDOR_FOR_UA")).toBe(false);
    });

    it("iOS suppression: Apple vendor on iOS never flags", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_SECTRANS }),
        device(
          SAFARI_IOS_UA,
          { jsEngine: "JavaScriptCore", layoutEngine: "WebKit" },
          { vendor: "Apple Computer, Inc." },
        ),
      );
      expect(hasCode(signals, "RARE_VENDOR_FOR_UA")).toBe(false);
    });
  });

  // ---- RARE_MATHS_FOR_UA ------------------------------------------------

  describe("RARE_MATHS_FOR_UA", () => {
    it("tampered math (lied=true) → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          {},
          { lied: true, hash: "abc", data: [] },
        ),
      );
      expect(hasCode(signals, "RARE_MATHS_FOR_UA")).toBe(true);
      const sig = signals.find((s) => s.code === "RARE_MATHS_FOR_UA")!;
      expect(sig.severity).toBe(0.8);
    });

    it("no math data → no signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(CHROME_UA, { jsEngine: "V8", layoutEngine: "Blink" }),
      );
      expect(hasCode(signals, "RARE_MATHS_FOR_UA")).toBe(false);
    });
  });

  // ---- RARE_WEBGL_VENDOR_FOR_UA -----------------------------------------

  describe("RARE_WEBGL_VENDOR_FOR_UA", () => {
    it("SwiftShader on desktop → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          { vendor: "Google Inc." },
          {},
          { scopes: { web: { webglRenderer: "Google SwiftShader" } } },
        ),
      );
      expect(hasCode(signals, "RARE_WEBGL_VENDOR_FOR_UA")).toBe(true);
    });

    it("llvmpipe on desktop → signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          {},
          {},
          {
            scopes: {
              web: { webglRenderer: "llvmpipe (LLVM 15.0.7, 256 bits)" },
            },
          },
        ),
      );
      expect(hasCode(signals, "RARE_WEBGL_VENDOR_FOR_UA")).toBe(true);
    });

    it("SwiftShader on mobile → no signal (low-end devices)", () => {
      // Use iPhone UA — ua-parser-js reliably classifies this as mobile
      const MOBILE_UA =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_SECTRANS }),
        device(
          MOBILE_UA,
          { jsEngine: "JavaScriptCore", layoutEngine: "WebKit" },
          { vendor: "Apple Computer, Inc." },
          {},
          { scopes: { web: { webglRenderer: "Apple GPU" } } },
        ),
      );
      // No software renderer on mobile Safari — this tests that non-desktop doesn't fire
      expect(hasCode(signals, "RARE_WEBGL_VENDOR_FOR_UA")).toBe(false);
    });

    it("software renderer on Android (non-desktop) → no signal", () => {
      // Android Chrome with "Mobile" token — ua-parser-js classifies as mobile
      const ANDROID_MOBILE_UA =
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36";
      // Pass UA via workerScope too, since extractUA prefers worker scope
      const signals = detectEngineCoherence(fp({ ja4: JA4_BORINGSSL }), {
        navigator: { userAgent: ANDROID_MOBILE_UA },
        engine: { jsEngine: "V8", layoutEngine: "Blink" },
        math: {},
        workerScope: {
          scopes: {
            web: {
              webglRenderer: "Google SwiftShader",
              userAgent: ANDROID_MOBILE_UA,
            },
          },
        },
      });
      expect(hasCode(signals, "RARE_WEBGL_VENDOR_FOR_UA")).toBe(false);
    });

    it("real GPU on desktop → no signal", () => {
      const signals = detectEngineCoherence(
        fp({ ja4: JA4_BORINGSSL }),
        device(
          CHROME_UA,
          { jsEngine: "V8", layoutEngine: "Blink" },
          {},
          {},
          {
            scopes: {
              web: { webglRenderer: "ANGLE (NVIDIA GeForce RTX 3080)" },
            },
          },
        ),
      );
      expect(hasCode(signals, "RARE_WEBGL_VENDOR_FOR_UA")).toBe(false);
    });
  });

  // ---- Graceful handling ------------------------------------------------

  describe("graceful handling of missing data", () => {
    it("empty device → no signals, no crash", () => {
      const signals = detectEngineCoherence(fp({ ja4: JA4_BORINGSSL }), {});
      expect(signals).toEqual([]);
    });

    it("undefined raw → no signals, no crash", () => {
      const signals = detectEngineCoherence(fp({ ja4: JA4_BORINGSSL }));
      expect(signals).toEqual([]);
    });

    it("null raw → no signals, no crash", () => {
      const signals = detectEngineCoherence(fp({ ja4: JA4_BORINGSSL }), null);
      expect(signals).toEqual([]);
    });

    it("no JA4 → only engine combo check runs", () => {
      const signals = detectEngineCoherence(
        fp({}),
        device(CHROME_UA, { jsEngine: "V8", layoutEngine: "Gecko" }),
      );
      // Engine combo should still fire without JA4
      expect(hasCode(signals, "RARE_ENGINE_COMBO")).toBe(true);
      // TLS-dependent checks should not fire
      expect(hasCode(signals, "RARE_ENGINE_FOR_UA")).toBe(false);
      expect(hasCode(signals, "RARE_VENDOR_FOR_UA")).toBe(false);
    });
  });
});
