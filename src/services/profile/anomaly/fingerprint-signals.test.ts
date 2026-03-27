import { describe, it, expect } from "vitest";
import { detectFingerprintSignals } from "./fingerprint-signals";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectFingerprintSignals", () => {
  describe("lie_count detection (removed)", () => {
    it("should not detect lie_count (detection removed from quick-wins)", () => {
      const fingerprint = { lie_count: 3 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.NAVIGATOR_LIES)).toBe(
        false,
      );
    });
  });

  describe("is_headless detection", () => {
    it("should detect when is_headless is true", () => {
      const fingerprint = { is_headless: true } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(true);
      const headlessSignal = signals.find(
        (s) => s.code === AnomalyCodes.HEADLESS_DETECTED,
      );
      expect(headlessSignal?.severity).toBe(0.9);
    });

    it("should not flag when is_headless is false", () => {
      const fingerprint = { is_headless: false } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(false);
    });

    it("should not flag when is_headless is undefined", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(false);
    });
  });

  describe("combined detections", () => {
    it("should detect multiple anomalies in same fingerprint", () => {
      const fingerprint = {
        lie_count: 2,
        is_headless: true,
      } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals).toHaveLength(1);
      expect(signals.map((s) => s.code)).toEqual([
        AnomalyCodes.HEADLESS_DETECTED,
      ]);
    });

    it("should return empty array for clean fingerprint", () => {
      const fingerprint = {
        lie_count: 0,
        is_headless: false,
      } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array for fingerprint with no relevant fields", () => {
      const fingerprint = {
        user_agent: "Mozilla/5.0",
        screen_dims: "1920x1080",
      } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals).toHaveLength(0);
    });
  });

  // ── Consistency checks (raw device payload) ──────────────────────────

  describe("screen vs CSS screenQuery mismatch", () => {
    it("should detect when screen dims differ from CSS screenQuery", () => {
      const fp = {} as Fingerprint;
      const raw = {
        screen: { width: 1920, height: 1080 },
        cssMedia: { screenQuery: { width: 1440, height: 900 } },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_CSS_MISMATCH),
      ).toBe(true);
      const sig = signals.find(
        (s) => s.code === AnomalyCodes.SCREEN_CSS_MISMATCH,
      )!;
      expect(sig.severity).toBe(0.9);
    });

    it("should not flag when screen and CSS screenQuery match", () => {
      const fp = {} as Fingerprint;
      const raw = {
        screen: { width: 1920, height: 1080 },
        cssMedia: { screenQuery: { width: 1920, height: 1080 } },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_CSS_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when screen or cssMedia is missing", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp, {
        screen: { width: 1920, height: 1080 },
      });

      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_CSS_MISMATCH),
      ).toBe(false);
    });
  });

  describe("audio noise detection", () => {
    it("should detect when audio noise > 0", () => {
      const fp = {} as Fingerprint;
      const raw = { offlineAudioContext: { noise: 0.0001 } };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.AUDIO_NOISE_DETECTED),
      ).toBe(true);
      const sig = signals.find(
        (s) => s.code === AnomalyCodes.AUDIO_NOISE_DETECTED,
      )!;
      expect(sig.severity).toBe(0.85);
    });

    it("should not flag when audio noise is 0", () => {
      const fp = {} as Fingerprint;
      const raw = { offlineAudioContext: { noise: 0 } };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.AUDIO_NOISE_DETECTED),
      ).toBe(false);
    });

    it("should not flag when offlineAudioContext is missing", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp, {});

      expect(
        signals.some((s) => s.code === AnomalyCodes.AUDIO_NOISE_DETECTED),
      ).toBe(false);
    });
  });

  describe("timezone offset mismatch", () => {
    it("should detect when main and worker timezone offsets differ", () => {
      const fp = {} as Fingerprint;
      const raw = {
        timezone: { offset: -300 },
        workerScope: { timezoneOffset: -240 },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.TIMEZONE_OFFSET_MISMATCH),
      ).toBe(true);
      const sig = signals.find(
        (s) => s.code === AnomalyCodes.TIMEZONE_OFFSET_MISMATCH,
      )!;
      expect(sig.severity).toBe(0.9);
    });

    it("should not flag when timezone offsets match", () => {
      const fp = {} as Fingerprint;
      const raw = {
        timezone: { offset: -300 },
        workerScope: { timezoneOffset: -300 },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.TIMEZONE_OFFSET_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when timezone or workerScope is missing", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp, {
        timezone: { offset: -300 },
      });

      expect(
        signals.some((s) => s.code === AnomalyCodes.TIMEZONE_OFFSET_MISMATCH),
      ).toBe(false);
    });
  });

  describe("touch coherence mismatch", () => {
    it("should detect when maxTouchPoints > 0 but screen.touch is false", () => {
      const fp = {} as Fingerprint;
      const raw = {
        navigator: { maxTouchPoints: 5 },
        screen: { touch: false },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(signals.some((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)).toBe(
        true,
      );
      const sig = signals.find((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)!;
      expect(sig.severity).toBe(0.7);
    });

    it("should detect when maxTouchPoints > 0 with pointer=fine, hover=hover, and touch=false", () => {
      const fp = {} as Fingerprint;
      const raw = {
        navigator: { maxTouchPoints: 5 },
        screen: { touch: false },
        cssMedia: { anyPointer: "fine", anyHover: "hover" },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(signals.some((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)).toBe(
        true,
      );
    });

    it("should not flag when maxTouchPoints is 0 (normal desktop)", () => {
      const fp = {} as Fingerprint;
      const raw = {
        navigator: { maxTouchPoints: 0 },
        screen: { touch: false },
        cssMedia: { anyPointer: "fine", anyHover: "hover" },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(signals.some((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)).toBe(
        false,
      );
    });

    it("should not flag when maxTouchPoints > 0 and screen.touch is true", () => {
      const fp = {} as Fingerprint;
      const raw = {
        navigator: { maxTouchPoints: 5 },
        screen: { touch: true },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(signals.some((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)).toBe(
        false,
      );
    });

    it("should not flag when navigator is missing", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp, {
        screen: { touch: false },
      });

      expect(signals.some((s) => s.code === AnomalyCodes.TOUCH_MISMATCH)).toBe(
        false,
      );
    });
  });

  describe("WebGL renderer cross-context mismatch", () => {
    it("should detect when main WebGL renderer differs from worker", () => {
      const fp = {} as Fingerprint;
      const raw = {
        canvasWebgl: {
          parameters: {
            UNMASKED_RENDERER_WEBGL: "ANGLE (NVIDIA GeForce GTX 1080)",
          },
        },
        workerScope: { webglRenderer: "ANGLE (Intel HD Graphics 630)" },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBGL_RENDERER_MISMATCH),
      ).toBe(true);
      const sig = signals.find(
        (s) => s.code === AnomalyCodes.WEBGL_RENDERER_MISMATCH,
      )!;
      expect(sig.severity).toBe(0.85);
    });

    it("should not flag when WebGL renderers match", () => {
      const fp = {} as Fingerprint;
      const renderer = "ANGLE (NVIDIA GeForce GTX 1080)";
      const raw = {
        canvasWebgl: { parameters: { UNMASKED_RENDERER_WEBGL: renderer } },
        workerScope: { webglRenderer: renderer },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBGL_RENDERER_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when canvasWebgl or workerScope is missing", () => {
      const fp = {} as Fingerprint;
      const raw = {
        canvasWebgl: {
          parameters: { UNMASKED_RENDERER_WEBGL: "ANGLE (NVIDIA)" },
        },
      };
      const signals = detectFingerprintSignals(fp, raw);

      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBGL_RENDERER_MISMATCH),
      ).toBe(false);
    });
  });

  describe("consistency checks with no raw payload", () => {
    it("should not run consistency checks when raw is undefined", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp);

      expect(signals).toHaveLength(0);
    });

    it("should not run consistency checks when raw is not an object", () => {
      const fp = {} as Fingerprint;
      const signals = detectFingerprintSignals(fp, "not-an-object");

      expect(signals).toHaveLength(0);
    });
  });

  describe("timezone offset vs computed mismatch", () => {
    it("should detect when offset !== offsetComputed", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        timezone: { offset: -300, offsetComputed: -240 },
      });
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
        ),
      ).toBe(true);
    });

    it("should not flag when offset equals offsetComputed", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        timezone: { offset: -300, offsetComputed: -300 },
      });
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
        ),
      ).toBe(false);
    });

    it("should not flag when timezone is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {});
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
        ),
      ).toBe(false);
    });

    it("should not flag when offsetComputed is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        timezone: { offset: -300 },
      });
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.TZ_OFFSET_COMPUTED_MISMATCH,
        ),
      ).toBe(false);
    });
  });

  describe("CSS media API mismatch (mediaCSS vs matchMediaCSS)", () => {
    it("should detect when mediaCSS and matchMediaCSS differ", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        cssMedia: {
          mediaCSS: { "color-gamut": "srgb", "prefers-color-scheme": "dark" },
          matchMediaCSS: {
            "color-gamut": "p3",
            "prefers-color-scheme": "dark",
          },
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.CSS_MEDIA_API_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when mediaCSS and matchMediaCSS match", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        cssMedia: {
          mediaCSS: { "color-gamut": "srgb" },
          matchMediaCSS: { "color-gamut": "srgb" },
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.CSS_MEDIA_API_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when matchMediaCSS is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        cssMedia: { mediaCSS: { "color-gamut": "srgb" } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.CSS_MEDIA_API_MISMATCH),
      ).toBe(false);
    });
  });

  describe("engine mismatch (consoleErrors)", () => {
    it("should detect when engineMismatch is true", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        consoleErrors: {
          engineMismatch: true,
          jsEngine: "v8",
          layoutEngine: "blink",
          claimedEngine: { browser: "Firefox" },
        },
      });
      expect(signals.some((s) => s.code === AnomalyCodes.ENGINE_MISMATCH)).toBe(
        true,
      );
    });

    it("should not flag when engineMismatch is false", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        consoleErrors: { engineMismatch: false },
      });
      expect(signals.some((s) => s.code === AnomalyCodes.ENGINE_MISMATCH)).toBe(
        false,
      );
    });

    it("should not flag when consoleErrors is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {});
      expect(signals.some((s) => s.code === AnomalyCodes.ENGINE_MISMATCH)).toBe(
        false,
      );
    });
  });

  describe("WebRTC IP mismatch", () => {
    it("should detect when WebRTC IP differs from connection IP", () => {
      const signals = detectFingerprintSignals(
        {} as Fingerprint,
        { webrtc: { iceCandidates: { publicIP: "1.2.3.4" } } },
        { tlsFingerprint: { ip: "5.6.7.8" } },
      );
      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when WebRTC IP matches connection IP", () => {
      const signals = detectFingerprintSignals(
        {} as Fingerprint,
        { webrtc: { iceCandidates: { publicIP: "1.2.3.4" } } },
        { tlsFingerprint: { ip: "1.2.3.4" } },
      );
      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when sigint is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        webrtc: { iceCandidates: { publicIP: "1.2.3.4" } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH),
      ).toBe(false);
    });

    it("should use tcpProbe IP when tlsFingerprint is absent", () => {
      const signals = detectFingerprintSignals(
        {} as Fingerprint,
        { webrtc: { iceCandidates: { publicIP: "1.2.3.4" } } },
        { tcpProbe: { client_ip: "5.6.7.8" } },
      );
      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when webrtc publicIP is missing", () => {
      const signals = detectFingerprintSignals(
        {} as Fingerprint,
        { webrtc: { iceCandidates: {} } },
        { tlsFingerprint: { ip: "5.6.7.8" } },
      );
      expect(
        signals.some((s) => s.code === AnomalyCodes.WEBRTC_IP_MISMATCH),
      ).toBe(false);
    });
  });

  describe("screen depth mismatch", () => {
    it("should detect when colorDepth !== pixelDepth", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { colorDepth: 24, pixelDepth: 32 },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_DEPTH_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when colorDepth === pixelDepth", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { colorDepth: 24, pixelDepth: 24 },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_DEPTH_MISMATCH),
      ).toBe(false);
    });
  });

  describe("screen avail overflow", () => {
    it("should detect when availWidth > width", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: {
          width: 1920,
          height: 1080,
          availWidth: 2000,
          availHeight: 1080,
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_AVAIL_OVERFLOW),
      ).toBe(true);
    });

    it("should detect when availHeight > height", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: {
          width: 1920,
          height: 1080,
          availWidth: 1920,
          availHeight: 1200,
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_AVAIL_OVERFLOW),
      ).toBe(true);
    });

    it("should not flag when avail <= screen dims", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: {
          width: 1920,
          height: 1080,
          availWidth: 1920,
          availHeight: 1040,
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.SCREEN_AVAIL_OVERFLOW),
      ).toBe(false);
    });
  });

  describe("device-screen string mismatch", () => {
    it("should detect when device-screen string doesn't match screen dims", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: { "device-screen": "1440 x 900" } },
      });
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.DEVICE_SCREEN_STRING_MISMATCH,
        ),
      ).toBe(true);
    });

    it("should not flag when device-screen matches screen dims", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: { "device-screen": "1920 x 1080" } },
      });
      expect(
        signals.some(
          (s) => s.code === AnomalyCodes.DEVICE_SCREEN_STRING_MISMATCH,
        ),
      ).toBe(false);
    });
  });

  describe("aspect ratio mismatch", () => {
    it("should detect when CSS aspect ratio doesn't match screen dims", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: { "device-aspect-ratio": "4/3" } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.ASPECT_RATIO_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when CSS aspect ratio matches screen dims", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: { "device-aspect-ratio": "16/9" } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.ASPECT_RATIO_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when aspect ratio string is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: {} },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.ASPECT_RATIO_MISMATCH),
      ).toBe(false);
    });

    it("should not flag for invalid ratio string", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        screen: { width: 1920, height: 1080 },
        cssMedia: { mediaCSS: { "device-aspect-ratio": "invalid" } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.ASPECT_RATIO_MISMATCH),
      ).toBe(false);
    });
  });

  describe("worker locale mismatch", () => {
    it("should detect when worker scopes have inconsistent locales", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        workerScope: {
          scopes: {
            dedicated: {
              language: "en-US",
              timezoneLocation: "America/New_York",
            },
            shared: { language: "fr-FR", timezoneLocation: "Europe/Paris" },
          },
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.WORKER_LOCALE_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when worker scopes have consistent locales", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        workerScope: {
          scopes: {
            dedicated: { language: "en-US" },
            shared: { language: "en-US" },
          },
        },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.WORKER_LOCALE_MISMATCH),
      ).toBe(false);
    });

    it("should not flag with only one scope", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        workerScope: { scopes: { dedicated: { language: "en-US" } } },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.WORKER_LOCALE_MISMATCH),
      ).toBe(false);
    });
  });

  describe("incognito browser mismatch", () => {
    it("should detect when incognito browser family differs from UA", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        incognito: { browser: "Chrome" },
        navigator: { userAgentParsed: "Firefox" },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.INCOGNITO_BROWSER_MISMATCH),
      ).toBe(true);
    });

    it("should not flag when browser families match (alias)", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        incognito: { browser: "CriOS" },
        navigator: { userAgentParsed: "Chrome" },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.INCOGNITO_BROWSER_MISMATCH),
      ).toBe(false);
    });

    it("should not flag when incognito is missing", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        navigator: { userAgentParsed: "Chrome" },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.INCOGNITO_BROWSER_MISMATCH),
      ).toBe(false);
    });

    it("should handle edge browser family normalization", () => {
      const signals = detectFingerprintSignals({} as Fingerprint, {
        incognito: { browser: "Edg" },
        navigator: { userAgentParsed: "Edge" },
      });
      expect(
        signals.some((s) => s.code === AnomalyCodes.INCOGNITO_BROWSER_MISMATCH),
      ).toBe(false);
    });
  });
});
