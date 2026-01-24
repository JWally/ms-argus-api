import { describe, it, expect } from "vitest";
import { detectNetworkAnomalies } from "./network";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectNetworkAnomalies", () => {
  describe("timezone mismatch detection", () => {
    it("should detect server timezone different from client timezone by >3 hours", () => {
      const fingerprint = {
        timezone: "America/Los_Angeles",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(true);
    });

    it("should detect large timezone mismatch (Asia vs US)", () => {
      const fingerprint = {
        timezone: "Asia/Tokyo",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(true);
    });

    it("should not flag matching timezones", () => {
      const fingerprint = {
        timezone: "America/New_York",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(false);
    });

    it("should not flag same offset different zone names", () => {
      const fingerprint = {
        timezone: "America/Detroit",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const tzMismatch = signals.filter(
        (s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH,
      );
      expect(tzMismatch.length === 0 || tzMismatch[0].severity < 0.5).toBe(
        true,
      );
    });

    it("should scale severity with timezone difference", () => {
      const fingerprint = {
        timezone: "Asia/Tokyo",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const tzSignal = signals.find(
        (s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH,
      );
      expect(tzSignal).toBeDefined();
      expect(tzSignal?.severity).toBeGreaterThan(0.6);
    });
  });

  describe("missing data handling (graceful degradation)", () => {
    it("should return empty array when sigint is undefined", () => {
      const fingerprint = {} as Fingerprint;

      const signals = detectNetworkAnomalies(fingerprint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array when geo is missing", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {};

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array when geo.timezone is missing", () => {
      const fingerprint = {
        timezone: "America/New_York",
      } as Fingerprint;
      const sigint = {
        geo: {},
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array when fingerprint.timezone is missing", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals).toHaveLength(0);
    });
  });

  describe("evidence formatting", () => {
    it("should include timezone info in evidence", () => {
      const fingerprint = {
        timezone: "Asia/Tokyo",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const tzSignal = signals.find(
        (s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH,
      );
      expect(tzSignal?.evidence.expected).toContain("America/New_York");
      expect(tzSignal?.evidence.actual).toContain("Asia/Tokyo");
    });
  });
});
