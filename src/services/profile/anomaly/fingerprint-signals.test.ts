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

  describe("proxy_score detection", () => {
    it("should detect when proxy_score > 0.7", () => {
      const fingerprint = { proxy_score: 0.85 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(true);
      const proxySignal = signals.find(
        (s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE,
      );
      expect(proxySignal?.severity).toBe(0.85);
      expect(proxySignal?.evidence.actual).toBe("proxy_score: 0.85");
    });

    it("should not flag when proxy_score is exactly 0.7", () => {
      const fingerprint = { proxy_score: 0.7 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });

    it("should not flag when proxy_score <= 0.7", () => {
      const fingerprint = { proxy_score: 0.5 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });

    it("should handle undefined proxy_score", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });
  });

  describe("vpn_score detection", () => {
    it("should detect when vpn_score > 0.7", () => {
      const fingerprint = { vpn_score: 0.9 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.HIGH_VPN_SCORE)).toBe(
        true,
      );
      const vpnSignal = signals.find(
        (s) => s.code === AnomalyCodes.HIGH_VPN_SCORE,
      );
      // Severity is vpn_score * 0.8
      expect(vpnSignal?.severity).toBeCloseTo(0.72, 2);
    });

    it("should not flag when vpn_score is exactly 0.7", () => {
      const fingerprint = { vpn_score: 0.7 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.HIGH_VPN_SCORE)).toBe(
        false,
      );
    });

    it("should not flag when vpn_score <= 0.7", () => {
      const fingerprint = { vpn_score: 0.3 } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.HIGH_VPN_SCORE)).toBe(
        false,
      );
    });
  });

  describe("combined detections", () => {
    it("should detect multiple anomalies in same fingerprint", () => {
      const fingerprint = {
        lie_count: 2,
        is_headless: true,
        proxy_score: 0.9,
        vpn_score: 0.8,
      } as Fingerprint;
      const signals = detectFingerprintSignals(fingerprint);

      expect(signals).toHaveLength(3);
      expect(signals.map((s) => s.code).sort()).toEqual(
        [
          AnomalyCodes.HEADLESS_DETECTED,
          AnomalyCodes.HIGH_PROXY_SCORE,
          AnomalyCodes.HIGH_VPN_SCORE,
        ].sort(),
      );
    });

    it("should return empty array for clean fingerprint", () => {
      const fingerprint = {
        lie_count: 0,
        is_headless: false,
        proxy_score: 0.1,
        vpn_score: 0.05,
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
});
