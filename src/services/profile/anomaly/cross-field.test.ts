// src/services/profile/anomaly/cross-field.test.ts
// AR-145: Tests for cross-field anomaly detection
// AR-143: Updated to use actual ms-argus-web payload structure

import { describe, it, expect } from "vitest";
import { detectCrossFieldAnomalies } from "./cross-field";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("detectCrossFieldAnomalies", () => {
  describe("navigator vs dedicated worker (workerScope.scopes.web)", () => {
    it("should detect when navigator.userAgent differs from dedicated worker", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
          },
          workerScope: {
            scopes: {
              web: {
                userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/537",
              },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.WORKER_MISMATCH);
      expect(signals[0].severity).toBe(0.8);
      expect(signals[0].evidence.fields).toContain("navigator.userAgent");
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
    });

    it("should not flag when userAgents match", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
          },
          workerScope: {
            scopes: {
              web: {
                userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
              },
            },
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
          workerScope: {
            scopes: {
              web: { userAgent: "Different UA" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.actual).toContain("...");
      expect(signals[0].evidence.actual.length).toBeLessThan(200);
    });
  });

  describe("platform mismatch", () => {
    it("should detect when navigator.platform differs from dedicated worker", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          workerScope: {
            scopes: {
              web: { platform: "MacIntel" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.WORKER_MISMATCH);
      expect(signals[0].severity).toBe(0.75);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.platform");
    });

    it("should not flag when platforms match", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          workerScope: {
            scopes: {
              web: { platform: "Win32" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("hardwareConcurrency mismatch", () => {
    it("should detect when navigator.hardwareConcurrency differs from worker", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          workerScope: {
            scopes: {
              web: { hardwareConcurrency: 4 },
            },
          },
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
          workerScope: {
            scopes: {
              web: { hardwareConcurrency: 8 },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(0);
    });
  });

  describe("multiple worker environments (scopes)", () => {
    it("should detect mismatch between navigator and shared worker", () => {
      const raw = {
        loose: {
          navigator: { platform: "Win32" },
          workerScope: {
            scopes: {
              shared: { platform: "Linux x86_64" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
      expect(signals[0].evidence.fields).toContain("sharedWorker.platform");
      expect(signals[0].evidence.actual).toContain("Shared Worker");
    });

    it("should detect mismatch between navigator and service worker", () => {
      const raw = {
        loose: {
          navigator: { hardwareConcurrency: 8 },
          workerScope: {
            scopes: {
              service: { hardwareConcurrency: 2 },
            },
          },
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
          navigator: { userAgent: "Chrome/120" }, // matches dedicated
          workerScope: {
            scopes: {
              web: { userAgent: "Chrome/120" },
              service: { userAgent: "Firefox/120" }, // mismatch
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // navigator vs service = 1 mismatch
      // dedicated vs service = 1 mismatch
      expect(signals).toHaveLength(2);
    });

    it("should detect all pairwise mismatches across multiple environments", () => {
      // Navigator spoofed, but all worker types left unspoofed
      const raw = {
        loose: {
          navigator: { userAgent: "Spoofed/1.0" },
          workerScope: {
            scopes: {
              web: { userAgent: "Chrome/120" },
              shared: { userAgent: "Chrome/120" },
              service: { userAgent: "Chrome/120" },
            },
          },
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
          workerScope: {
            scopes: {
              web: { platform: "Spoofed" },
              service: { platform: "Win32" }, // Forgot this one
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // navigator vs serviceWorker = 1 mismatch
      // dedicatedWorker vs serviceWorker = 1 mismatch
      // navigator vs dedicatedWorker = match
      expect(signals).toHaveLength(2);
    });

    it("should handle all four environment types", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "A" },
          workerScope: {
            scopes: {
              web: { userAgent: "B" },
              shared: { userAgent: "C" },
              service: { userAgent: "D" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // 4 environments with all different values
      // Pairs: 4 choose 2 = 6 pairs, all mismatched
      expect(signals).toHaveLength(6);
    });
  });

  describe("unavailable worker types", () => {
    it("should skip shared worker when null", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: {
            scopes: {
              web: { userAgent: "Firefox/120" },
              shared: null, // Not available
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Only navigator vs dedicated worker
      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
    });

    it("should skip service worker when 'unavailable' string", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: {
            scopes: {
              web: { userAgent: "Firefox/120" },
              service: "unavailable", // Blocked
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Only navigator vs dedicated worker
      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
    });
  });

  describe("legacy workerScope fallback", () => {
    it("should use top-level workerScope when scopes not present", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Chrome/120",
          },
          workerScope: {
            userAgent: "Firefox/120",
            // No scopes property - legacy format
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("workerScope.userAgent");
    });

    it("should prefer scopes over top-level workerScope when both present", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: {
            userAgent: "TopLevel/1.0", // Should be ignored
            scopes: {
              web: { userAgent: "Firefox/120" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("dedicatedWorker.userAgent");
      expect(signals[0].evidence.actual).not.toContain("TopLevel");
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
            scopes: {
              web: {
                userAgent: "Firefox/120",
                platform: "Linux x86_64",
                hardwareConcurrency: 4,
              },
            },
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

    it("should return empty array when only navigator exists", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
        },
      };
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should return empty array when workerScope has no usable scopes", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: {
            scopes: {
              shared: null,
              service: "unavailable",
            },
          },
        },
      };
      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);
      expect(signals).toHaveLength(0);
    });

    it("should handle missing individual fields gracefully", () => {
      const raw = {
        loose: {
          navigator: { userAgent: "Chrome/120" },
          workerScope: {
            scopes: {
              web: { platform: "Win32" }, // No userAgent
            },
          },
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
            scopes: {
              web: {
                userAgent: "Firefox/120",
                // platform missing
              },
            },
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
    it("should return empty array for matching navigator and worker", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
            platform: "Win32",
            hardwareConcurrency: 8,
          },
          workerScope: {
            scopes: {
              web: {
                userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
                platform: "Win32",
                hardwareConcurrency: 8,
              },
            },
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
          workerScope: {
            scopes: {
              web: { userAgent: "Chrome/120", platform: "Win32" },
              shared: { userAgent: "Chrome/120", platform: "Win32" },
              service: { userAgent: "Chrome/120", platform: "Win32" },
            },
          },
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
          workerScope: {
            scopes: {
              service: { userAgent: "Firefox" },
            },
          },
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
          workerScope: {
            scopes: {
              web: { userAgent: "Chrome", platform: "MacIntel" },
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // Should only detect platform mismatch (userAgent undefined in one)
      expect(signals).toHaveLength(1);
      expect(signals[0].evidence.fields).toContain("navigator.platform");
    });
  });

  describe("real payload structure", () => {
    it("should work with actual ms-argus-web payload structure", () => {
      // Based on actual payload from S3 archive
      const raw = {
        loose: {
          navigator: {
            userAgent:
              "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
            platform: "Linux x86_64",
            hardwareConcurrency: 12,
          },
          workerScope: {
            userAgent:
              "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
            platform: "Linux x86_64",
            hardwareConcurrency: 12,
            scopes: {
              main: {
                hardwareConcurrency: 12,
                language: "en-US",
                platform: "Linux x86_64",
                userAgent:
                  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
              },
              web: {
                hardwareConcurrency: 12,
                language: "en-US",
                platform: "Linux x86_64",
                userAgent:
                  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
              },
              shared: null,
              service: "unavailable",
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // All values match - should be clean
      expect(signals).toHaveLength(0);
    });

    it("should detect spoofing in real payload structure", () => {
      const raw = {
        loose: {
          navigator: {
            userAgent: "Spoofed/1.0 (fake browser)",
            platform: "FakeOS",
            hardwareConcurrency: 99,
          },
          workerScope: {
            scopes: {
              web: {
                userAgent:
                  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/147.0",
                platform: "Linux x86_64",
                hardwareConcurrency: 12,
              },
              shared: null,
              service: "unavailable",
            },
          },
        },
      };

      const signals = detectCrossFieldAnomalies({} as Fingerprint, raw);

      // All 3 fields mismatch between navigator and dedicated worker
      expect(signals).toHaveLength(3);
      expect(signals.map((s) => s.severity).sort()).toEqual([0.7, 0.75, 0.8]);
    });
  });
});
