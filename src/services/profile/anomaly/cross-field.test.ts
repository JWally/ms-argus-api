// src/services/profile/anomaly/cross-field.test.ts
// AR-145: Tests for cross-field anomaly detection

import { describe, it, expect } from "vitest";
import { detectCrossFieldAnomalies } from "./cross-field";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectCrossFieldAnomalies", () => {
  describe("userAgent mismatch", () => {
    it("should detect when navigator.userAgent differs from workerScope.userAgent", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
          },
          workerScope: {
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537",
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.WORKER_MISMATCH);
      expect(signals[0].severity).toBe(0.8);
      expect(signals[0].evidence.fields).toContain("navigator.userAgent");
      expect(signals[0].evidence.fields).toContain("workerScope.userAgent");
    });

    it("should not flag when userAgents match", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
          },
          workerScope: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(
        signals.some(
          (s) =>
            s.evidence.fields?.includes("navigator.userAgent") &&
            s.evidence.fields?.includes("workerScope.userAgent"),
        ),
      ).toBe(false);
    });

    it("should truncate long userAgent strings in evidence", () => {
      const longUA = "A".repeat(100);
      const raw = {
        loose: {
          navigator: { userAgent: longUA },
          workerScope: { userAgent: "Different UA" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.actual).toContain("...");
      expect(signals[0].evidence.actual.length).toBeLessThan(200);
    });
  });

  describe("platform mismatch", () => {
    it("should detect when navigator.platform differs from workerScope.platform", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          workerScope: { platform: "MacIntel" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.WORKER_MISMATCH);
      expect(signals[0].severity).toBe(0.75);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
      expect(signals[0].evidence.fields).toContain("workerScope.platform");
    });

    it("should not flag when platforms match", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          workerScope: { platform: "Win32" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(
        signals.some(
          (s) =>
            s.evidence.fields?.includes("navigator.platform") &&
            s.evidence.fields?.includes("workerScope.platform"),
        ),
      ).toBe(false);
    });
  });

  describe("hardwareConcurrency mismatch", () => {
    it("should detect when navigator.hardwareConcurrency differs from workerScope", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          workerScope: { hardwareConcurrency: 4 },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.WORKER_MISMATCH);
      expect(signals[0].severity).toBe(0.7);
      expect(signals[0].evidence.actual).toContain("Navigator: 8");
      expect(signals[0].evidence.actual).toContain("Worker: 4");
    });

    it("should not flag when hardwareConcurrency matches", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          workerScope: { hardwareConcurrency: 8 },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(
        signals.some((s) =>
          s.evidence.fields?.includes("navigator.hardwareConcurrency"),
        ),
      ).toBe(false);
    });
  });

  describe("multiple mismatches", () => {
    it("should detect all mismatches in same payload", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Chrome/120",
            platform: "Win32",
            hardwareConcurrency: 8,
          },
          workerScope: {
            userAgent: "Firefox/120",
            platform: "Linux x86_64",
            hardwareConcurrency: 4,
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(3);
      expect(
        signals.every((s) => s.code === AnomalyCodes.WORKER_MISMATCH),
      ).toBe(true);
    });
  });

  describe("missing data handling", () => {
    it("should return empty array when raw is undefined", () => {
      const signals = detectCrossFieldAnomalies({} as Fingerprint, undefined);
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when raw is null", () => {
      const signals = detectCrossFieldAnomalies({} as Fingerprint, null);
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when raw is not an object", () => {
      const signals = detectCrossFieldAnomalies({} as Fingerprint, "string");
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when loose is missing", () => {
      const raw = { other: "data" };
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when navigator is missing", () => {
      const raw = {
        loose: {
          workerScope: { userAgent: "Firefox/120" },
        },
      };
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when workerScope is missing", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
        },
      };
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should handle missing individual fields gracefully", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: { platform: "Win32" },
        },
      };

      // No overlapping fields to compare
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should only compare fields present in both scopes", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Chrome/120",
            platform: "Win32",
          },
          workerScope: {
            userAgent: "Firefox/120",
            // platform missing
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Only userAgent mismatch should be detected
      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.userAgent");
    });
  });

  describe("clean fingerprints", () => {
    it("should return empty array for matching navigator and worker scopes", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
            platform: "Win32",
            hardwareConcurrency: 8,
          },
          workerScope: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
            platform: "Win32",
            hardwareConcurrency: 8,
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });
  });
});
