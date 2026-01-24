import { describe, it, expect } from "vitest";
import { detectQuickWinAnomalies } from "./quick-wins";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectQuickWinAnomalies", () => {
  describe("lie_count detection", () => {
    it("should detect when lie_count > 0", () => {
      const fingerprint = { lie_count: 3 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.NAVIGATOR_LIES);
      // 0.5 base + 0.3 (3 * 0.1) = 0.8
      expect(signals[0].severity).toBeCloseTo(0.8, 2);
      expect(signals[0].evidence.expected).toBe("0 lies");
      expect(signals[0].evidence.actual).toBe("3 lies detected");
    });

    it("should cap severity at 0.9 for high lie counts", () => {
      const fingerprint = { lie_count: 10 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(1);
      // 0.5 + 1.0 would be 1.5, but capped at 0.9
      expect(signals[0].severity).toBe(0.9);
    });

    it("should not flag when lie_count is 0", () => {
      const fingerprint = { lie_count: 0 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.NAVIGATOR_LIES)).toBe(
        false,
      );
    });

    it("should handle undefined lie_count", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.NAVIGATOR_LIES)).toBe(
        false,
      );
    });

    it("should have correct severity for single lie", () => {
      const fingerprint = { lie_count: 1 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(1);
      // 0.5 + 0.1 = 0.6
      expect(signals[0].severity).toBeCloseTo(0.6, 2);
    });
  });

  describe("is_headless detection", () => {
    it("should detect when is_headless is true", () => {
      const fingerprint = { is_headless: true } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

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
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(false);
    });

    it("should not flag when is_headless is undefined", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HEADLESS_DETECTED),
      ).toBe(false);
    });
  });

  describe("proxy_score detection", () => {
    it("should detect when proxy_score > 0.7", () => {
      const fingerprint = { proxy_score: 0.85 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

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
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });

    it("should not flag when proxy_score <= 0.7", () => {
      const fingerprint = { proxy_score: 0.5 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });

    it("should handle undefined proxy_score", () => {
      const fingerprint = {} as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.HIGH_PROXY_SCORE),
      ).toBe(false);
    });
  });

  describe("vpn_score detection", () => {
    it("should detect when vpn_score > 0.7", () => {
      const fingerprint = { vpn_score: 0.9 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

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
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals.some((s) => s.code === AnomalyCodes.HIGH_VPN_SCORE)).toBe(
        false,
      );
    });

    it("should not flag when vpn_score <= 0.7", () => {
      const fingerprint = { vpn_score: 0.3 } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

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
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(4);
      expect(signals.map((s) => s.code).sort()).toEqual(
        [
          AnomalyCodes.HEADLESS_DETECTED,
          AnomalyCodes.HIGH_PROXY_SCORE,
          AnomalyCodes.HIGH_VPN_SCORE,
          AnomalyCodes.NAVIGATOR_LIES,
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
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array for fingerprint with no relevant fields", () => {
      const fingerprint = {
        user_agent: "Mozilla/5.0",
        screen_dims: "1920x1080",
      } as Fingerprint;
      const signals = detectQuickWinAnomalies(fingerprint);

      expect(signals).toHaveLength(0);
    });
  });
});
