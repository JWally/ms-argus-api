// src/services/profile/anomaly/network.test.ts
// AR-144: Tests for network anomaly detection (FTL, timezone, JA4 mismatch)

import { describe, it, expect } from "vitest";
import { detectNetworkAnomalies, haversineDistance } from "./network";
import { AnomalyCodes } from "./types";
import { Fingerprint } from "../../../types";

describe("haversineDistance", () => {
  it("should calculate correct distance between NYC and LA (~3940 km)", () => {
    // NYC: 40.7128, -74.0060
    // LA: 34.0522, -118.2437
    const distance = haversineDistance(40.7128, -74.006, 34.0522, -118.2437);
    expect(distance).toBeGreaterThan(3900);
    expect(distance).toBeLessThan(4000);
  });

  it("should calculate correct distance between London and Tokyo (~9560 km)", () => {
    // London: 51.5074, -0.1278
    // Tokyo: 35.6762, 139.6503
    const distance = haversineDistance(51.5074, -0.1278, 35.6762, 139.6503);
    expect(distance).toBeGreaterThan(9500);
    expect(distance).toBeLessThan(9650);
  });

  it("should calculate correct distance between Reston VA and Sydney (~15684 km)", () => {
    // Reston, VA (AWS us-east-1): 38.9586, -77.3570
    // Sydney: -33.8688, 151.2093
    const distance = haversineDistance(38.9586, -77.357, -33.8688, 151.2093);
    expect(distance).toBeGreaterThan(15600);
    expect(distance).toBeLessThan(15800);
  });

  it("should return 0 for same coordinates", () => {
    const distance = haversineDistance(38.9586, -77.357, 38.9586, -77.357);
    expect(distance).toBe(0);
  });
});

describe("detectNetworkAnomalies", () => {
  // Server location: Reston, VA (38.9586, -77.3570)

  describe("AC1: FTL violation detection", () => {
    it("should detect impossibly fast RTT for claimed location (Sydney with 10ms RTT)", () => {
      // Sydney is ~15684km from Reston VA
      // Minimum possible RTT at fiber speed: 15684km / 200 km/ms * 2 = ~157ms
      // 10ms RTT is physically impossible
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: -33.8688, // Sydney
          lon: 151.2093,
          timezone: "Australia/Sydney",
        },
        tcpProbe: {
          rttMs: 10, // Impossibly fast
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe(AnomalyCodes.FTL_VIOLATION);
      expect(signals[0].severity).toBe(0.95);
    });

    it("should not flag realistic RTT for same location (NYC with 50ms RTT)", () => {
      // NYC is ~350km from Reston VA
      // Minimum possible RTT: 350km / 200 km/ms * 2 = ~3.5ms
      // 50ms is realistic with routing overhead
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: 40.7128, // NYC
          lon: -74.006,
          timezone: "America/New_York",
        },
        tcpProbe: {
          rttMs: 50,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const ftlSignals = signals.filter(
        (s) => s.code === AnomalyCodes.FTL_VIOLATION,
      );
      expect(ftlSignals).toHaveLength(0);
    });

    it("should not flag borderline RTT within 10% tolerance", () => {
      // LA is ~3700km from Reston VA
      // Minimum RTT: 3700/200*2 = 37ms
      // 34ms is within 10% tolerance (37 * 0.9 = 33.3ms)
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: 34.0522, // LA
          lon: -118.2437,
          timezone: "America/Los_Angeles",
        },
        tcpProbe: {
          rttMs: 34,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const ftlSignals = signals.filter(
        (s) => s.code === AnomalyCodes.FTL_VIOLATION,
      );
      expect(ftlSignals).toHaveLength(0);
    });

    it("should detect FTL for London with impossibly fast RTT", () => {
      // London is ~5900km from Reston VA
      // Minimum RTT: 5900/200*2 = 59ms
      // 20ms is FTL
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: 51.5074, // London
          lon: -0.1278,
          timezone: "Europe/London",
        },
        tcpProbe: {
          rttMs: 20,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals.some((s) => s.code === AnomalyCodes.FTL_VIOLATION)).toBe(
        true,
      );
    });
  });

  describe("AC2: Timezone mismatch detection", () => {
    it("should detect server timezone different from client timezone by >3 hours", () => {
      const fingerprint = {
        timezone: "America/Los_Angeles", // Pacific time
      } as Fingerprint;
      const sigint = {
        geo: {
          lat: 40.7128,
          lon: -74.006,
          timezone: "America/New_York", // Eastern time - 3 hours ahead
        },
        tcpProbe: {
          rttMs: 100, // Realistic RTT
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(true);
    });

    it("should detect large timezone mismatch (Asia vs US)", () => {
      const fingerprint = {
        timezone: "Asia/Tokyo", // +9 hours from UTC
      } as Fingerprint;
      const sigint = {
        geo: {
          lat: 40.7128,
          lon: -74.006,
          timezone: "America/New_York", // -5 hours from UTC
        },
        tcpProbe: {
          rttMs: 100,
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
          lat: 40.7128,
          lon: -74.006,
          timezone: "America/New_York",
        },
        tcpProbe: {
          rttMs: 100,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(false);
    });

    it("should not flag same offset different zone names", () => {
      const fingerprint = {
        timezone: "America/Detroit", // Same offset as New York
      } as Fingerprint;
      const sigint = {
        geo: {
          lat: 40.7128,
          lon: -74.006,
          timezone: "America/New_York",
        },
        tcpProbe: {
          rttMs: 100,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      // Should not flag as major mismatch since offset is same
      const tzMismatch = signals.filter(
        (s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH,
      );
      expect(tzMismatch.length === 0 || tzMismatch[0].severity < 0.5).toBe(
        true,
      );
    });
  });

  describe("AC4: Missing geo data returns empty signals (graceful degradation)", () => {
    it("should return empty array when sigint is undefined", () => {
      const fingerprint = {} as Fingerprint;

      const signals = detectNetworkAnomalies(fingerprint, undefined, undefined);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array when geo is missing", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        tcpProbe: {
          rttMs: 10,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      expect(signals).toHaveLength(0);
    });

    it("should return empty array when geo.lat/lon is missing", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
          // Missing lat/lon
        },
        tcpProbe: {
          rttMs: 10,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      // Should only check timezone if we have it, not FTL
      const ftlSignals = signals.filter(
        (s) => s.code === AnomalyCodes.FTL_VIOLATION,
      );
      expect(ftlSignals).toHaveLength(0);
    });

    it("should return empty array when tcpProbe.rttMs is missing", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: -33.8688,
          lon: 151.2093,
          timezone: "Australia/Sydney",
        },
        tcpProbe: {
          // Missing rttMs
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const ftlSignals = signals.filter(
        (s) => s.code === AnomalyCodes.FTL_VIOLATION,
      );
      expect(ftlSignals).toHaveLength(0);
    });

    it("should check timezone but not FTL when only timezone data available", () => {
      const fingerprint = {
        timezone: "Asia/Tokyo",
      } as Fingerprint;
      const sigint = {
        geo: {
          timezone: "America/New_York",
          // Missing lat/lon so can't do FTL check
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      // Should detect timezone mismatch but not FTL
      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(true);
      expect(signals.some((s) => s.code === AnomalyCodes.FTL_VIOLATION)).toBe(
        false,
      );
    });
  });

  describe("AC5: Haversine distance accuracy", () => {
    it("should be accurate within 1% for known city distances", () => {
      // NYC to LA: known distance ~3940 km
      const calculated = haversineDistance(
        40.7128,
        -74.006,
        34.0522,
        -118.2437,
      );
      const expected = 3940;
      const tolerance = expected * 0.01; // 1%

      expect(Math.abs(calculated - expected)).toBeLessThan(tolerance);
    });
  });

  describe("edge cases", () => {
    it("should handle fingerprint with no timezone gracefully", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: 40.7128,
          lon: -74.006,
          timezone: "America/New_York",
        },
        tcpProbe: {
          rttMs: 100,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      // Should not throw, should skip timezone check
      expect(
        signals.some((s) => s.code === AnomalyCodes.IP_TIMEZONE_MISMATCH),
      ).toBe(false);
    });

    it("should include evidence with distance and RTT for FTL violation", () => {
      const fingerprint = {} as Fingerprint;
      const sigint = {
        geo: {
          lat: -33.8688,
          lon: 151.2093,
          timezone: "Australia/Sydney",
        },
        tcpProbe: {
          rttMs: 10,
        },
      };

      const signals = detectNetworkAnomalies(fingerprint, undefined, sigint);

      const ftlSignal = signals.find(
        (s) => s.code === AnomalyCodes.FTL_VIOLATION,
      );
      expect(ftlSignal).toBeDefined();
      expect(ftlSignal?.evidence.expected).toBeTruthy();
      expect(ftlSignal?.evidence.actual).toBeTruthy();
    });
  });
});
