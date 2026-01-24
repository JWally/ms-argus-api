// src/services/profile/anomaly/anomaly.test.ts
// AR-141: Tests for anomaly detection foundation
// AR-158: Updated to mock Powertools logger/metrics instead of console.error

import { describe, it, expect, vi } from "vitest";

// AR-158: Mock Powertools - must use vi.hoisted to create mocks before vi.mock runs
const { mockLoggerError, mockAddMetric } = vi.hoisted(() => ({
  mockLoggerError: vi.fn(),
  mockAddMetric: vi.fn(),
}));

vi.mock("@aws-lambda-powertools/logger", () => ({
  Logger: vi.fn().mockImplementation(() => ({
    error: mockLoggerError,
  })),
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: mockAddMetric,
  })),
  MetricUnit: { Count: "Count" },
}));
import { AnomalyCodes, AnomalySignal, createSignal } from "./types";
import {
  detectAllAnomalies,
  registerDetector,
  getDetectorCount,
} from "./detector";
import { Fingerprint } from "../../../types";

describe("Anomaly Detection Foundation", () => {
  describe("createSignal", () => {
    it("should create a valid signal with all fields", () => {
      const signal = createSignal("CROSS_FIELD", AnomalyCodes.NAVIGATOR_LIES, 0.7, {
        expected: "expected value",
        actual: "actual value",
        fields: ["field1", "field2"],
      });

      expect(signal.type).toBe("CROSS_FIELD");
      expect(signal.code).toBe("NAVIGATOR_LIES");
      expect(signal.severity).toBe(0.7);
      expect(signal.evidence.expected).toBe("expected value");
      expect(signal.evidence.actual).toBe("actual value");
      expect(signal.evidence.fields).toEqual(["field1", "field2"]);
    });

    it("should clamp severity to maximum of 1.0", () => {
      const signal = createSignal("NETWORK", AnomalyCodes.IP_TIMEZONE_MISMATCH, 1.5, {
        expected: "expected",
        actual: "actual",
      });

      expect(signal.severity).toBe(1.0);
    });

    it("should clamp severity to minimum of 0.0", () => {
      const signal = createSignal("CROSS_FIELD", AnomalyCodes.WORKER_MISMATCH, -0.5, {
        expected: "expected",
        actual: "actual",
      });

      expect(signal.severity).toBe(0.0);
    });

    it("should work without optional fields parameter", () => {
      const signal = createSignal("IDENTITY", AnomalyCodes.HEADLESS_DETECTED, 0.9, {
        expected: "false",
        actual: "true",
      });

      expect(signal.evidence.fields).toBeUndefined();
    });
  });

  describe("AnomalyCodes", () => {
    it("should have all expected anomaly codes", () => {
      expect(AnomalyCodes.NAVIGATOR_LIES).toBe("NAVIGATOR_LIES");
      expect(AnomalyCodes.WORKER_MISMATCH).toBe("WORKER_MISMATCH");
      expect(AnomalyCodes.IP_TIMEZONE_MISMATCH).toBe("IP_TIMEZONE_MISMATCH");
      expect(AnomalyCodes.HEADLESS_DETECTED).toBe("HEADLESS_DETECTED");
      expect(AnomalyCodes.HIGH_PROXY_SCORE).toBe("HIGH_PROXY_SCORE");
      expect(AnomalyCodes.HIGH_VPN_SCORE).toBe("HIGH_VPN_SCORE");
    });
  });

  describe("detectAllAnomalies", () => {
    it("should return empty result when no detectors registered", () => {
      const fingerprint = {} as Fingerprint;
      const result = detectAllAnomalies(fingerprint);

      expect(result.signals).toEqual([]);
      expect(result.aggregateScore).toBe(0);
      expect(result.suggestedFlags).toEqual([]);
    });

    it("should catch detector errors and continue", () => {
      // AR-158: Clear mocks before test
      mockLoggerError.mockClear();
      mockAddMetric.mockClear();

      // Register a detector that throws
      const throwingDetector = (): AnomalySignal[] => {
        throw new Error("Test error");
      };
      registerDetector(throwingDetector);

      const fingerprint = {} as Fingerprint;

      // Should not throw
      expect(() => detectAllAnomalies(fingerprint)).not.toThrow();

      // AR-158: Should log via Powertools logger and emit metric
      expect(mockLoggerError).toHaveBeenCalled();
      expect(mockAddMetric).toHaveBeenCalledWith(
        "AnomalyDetectorError",
        "Count",
        1,
      );
    });

    it("should aggregate scores from signals", () => {
      // Register a detector that returns signals
      const testDetector = (): AnomalySignal[] => [
        createSignal("CROSS_FIELD", AnomalyCodes.NAVIGATOR_LIES, 0.3, {
          expected: "0",
          actual: "3",
        }),
        createSignal("NETWORK", AnomalyCodes.HIGH_PROXY_SCORE, 0.4, {
          expected: "0.5",
          actual: "0.8",
        }),
      ];
      registerDetector(testDetector);

      const fingerprint = {} as Fingerprint;
      const result = detectAllAnomalies(fingerprint);

      // Should have signals from our detector (plus potentially from previous test's throwing detector)
      expect(result.signals.length).toBeGreaterThanOrEqual(2);
      // Aggregate score should be sum of severities, capped at 1.0
      expect(result.aggregateScore).toBeGreaterThanOrEqual(0.7);
    });

    it("should cap aggregate score at 1.0", () => {
      // Register a detector that returns high-severity signals
      const highSeverityDetector = (): AnomalySignal[] => [
        createSignal("NETWORK", AnomalyCodes.IP_TIMEZONE_MISMATCH, 0.95, {
          expected: "America/New_York",
          actual: "Asia/Tokyo",
        }),
        createSignal("CROSS_FIELD", AnomalyCodes.WORKER_MISMATCH, 0.8, {
          expected: "Chrome",
          actual: "Firefox",
        }),
      ];
      registerDetector(highSeverityDetector);

      const fingerprint = {} as Fingerprint;
      const result = detectAllAnomalies(fingerprint);

      // Aggregate score should be capped at 1.0
      expect(result.aggregateScore).toBeLessThanOrEqual(1.0);
    });

    it("should convert anomaly codes to lowercase flags", () => {
      // The detector registered in previous test should have created flags
      const fingerprint = {} as Fingerprint;
      const result = detectAllAnomalies(fingerprint);

      // Check that suggested flags are lowercase
      for (const flag of result.suggestedFlags) {
        expect(flag).toBe(flag.toLowerCase());
      }
    });
  });

  describe("getDetectorCount", () => {
    it("should return the number of registered detectors", () => {
      const count = getDetectorCount();
      // We registered detectors in previous tests
      expect(count).toBeGreaterThan(0);
    });
  });
});
