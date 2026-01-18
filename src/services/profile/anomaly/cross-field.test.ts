// src/services/profile/anomaly/cross-field.test.ts
// AR-145: Tests for cross-field anomaly detection
// Extended to cover multiple worker environments

import { describe, it, expect } from "vitest";
import { detectCrossFieldAnomalies } from "./cross-field";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectCrossFieldAnomalies", () => {
  describe("navigator vs workerScope (legacy)", () => {
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

      expect(signals).toHaveLength(0);
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

      expect(signals).toHaveLength(0);
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
      expect(signals[0].evidence.actual).toContain("8");
      expect(signals[0].evidence.actual).toContain("4");
    });

    it("should not flag when hardwareConcurrency matches", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          workerScope: { hardwareConcurrency: 8 },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("multiple worker environments", () => {
    it("should detect mismatch between navigator and dedicatedWorker", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120", platform: "Win32" },
          dedicatedWorker: { userAgent: "Firefox/120", platform: "Win32" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.userAgent");
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
      expect(signals[0].evidence.actual).toContain("Dedicated Worker");
    });

    it("should detect mismatch between navigator and sharedWorker", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          sharedWorker: { platform: "Linux x86_64" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
      expect(signals[0].evidence.fields).toContain("sharedWorker.platform");
      expect(signals[0].evidence.actual).toContain("Shared Worker");
    });

    it("should detect mismatch between navigator and serviceWorker", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          serviceWorker: { hardwareConcurrency: 2 },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain(
        "navigator.hardwareConcurrency",
      );
      expect(signals[0].evidence.fields).toContain(
        "serviceWorker.hardwareConcurrency",
      );
      expect(signals[0].evidence.actual).toContain("Service Worker");
    });

    it("should detect mismatches between different worker types", () => {
      const raw = {
        loose: {
          dedicatedWorker: { userAgent: "Chrome/120" },
          serviceWorker: { userAgent: "Firefox/120" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
      expect(signals[0].evidence.fields).toContain("serviceWorker.userAgent");
    });

    it("should detect all pairwise mismatches across multiple environments", () => {
      // Navigator spoofed, but all three worker types left unspoofed
      const raw = {
        loose: {
          navigator: { userAgent: "Spoofed/1.0" },
          dedicatedWorker: { userAgent: "Chrome/120" },
          sharedWorker: { userAgent: "Chrome/120" },
          serviceWorker: { userAgent: "Chrome/120" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Navigator vs each worker = 3 mismatches
      // Workers match each other = 0 mismatches
      expect(signals).toHaveLength(3);

      // All should be userAgent mismatches
      expect(
        signals.every((s) => s.code === AnomalyCodes.WORKER_MISMATCH),
      ).toBe(true);
    });

    it("should detect when one worker type is spoofed but others are not", () => {
      // Attacker spoofed navigator and dedicated worker, forgot service worker
      const raw = {
        loose: {
          navigator: { platform: "Spoofed" },
          dedicatedWorker: { platform: "Spoofed" },
          serviceWorker: { platform: "Win32" }, // Forgot this one
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // navigator vs serviceWorker = 1 mismatch
      // dedicatedWorker vs serviceWorker = 1 mismatch
      // navigator vs dedicatedWorker = match
      expect(signals).toHaveLength(2);
    });

    it("should handle all five environment types", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "A" },
          workerScope: { userAgent: "B" },
          dedicatedWorker: { userAgent: "C" },
          sharedWorker: { userAgent: "D" },
          serviceWorker: { userAgent: "E" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // 5 environments with all different values
      // Pairs: 5 choose 2 = 10 pairs, all mismatched
      expect(signals).toHaveLength(10);
    });
  });

  describe("multiple mismatches in same environment pair", () => {
    it("should detect all mismatches between two environments", () => {
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

    it("should return empty array when only one environment exists", () => {
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

    it("should only compare fields present in both environments", () => {
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

    it("should return empty array when all environments match", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120", platform: "Win32" },
          dedicatedWorker: { userAgent: "Chrome/120", platform: "Win32" },
          sharedWorker: { userAgent: "Chrome/120", platform: "Win32" },
          serviceWorker: { userAgent: "Chrome/120", platform: "Win32" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });
  });

  describe("evidence formatting", () => {
    it("should include human-readable environment names in evidence", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome" },
          serviceWorker: { userAgent: "Firefox" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals[0].evidence.expected).toContain("Navigator (main)");
      expect(signals[0].evidence.actual).toContain("Service Worker");
    });

    it("should handle undefined values in truncation", () => {
      const raw = {
        loose: {
          navigator: { userAgent: undefined, platform: "Win32" },
          workerScope: { userAgent: "Chrome", platform: "MacIntel" },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Should only detect platform mismatch (userAgent undefined in one)
      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
    });
  });
});
