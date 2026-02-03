import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the cache module before importing
vi.mock("../../cache", () => ({
  recordAndGetStats: vi.fn(),
  isValkeyEnabled: vi.fn(),
}));

// Mock powertools
vi.mock("@aws-lambda-powertools/logger", () => ({
  Logger: vi.fn().mockImplementation(() => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  })),
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: vi.fn(),
  })),
  MetricUnit: {
    NoUnit: "None",
    Count: "Count",
  },
}));

import {
  fetchStatisticalContext,
  detectStatisticalAnomalies,
} from "./statistical";
import { recordAndGetStats, isValkeyEnabled } from "../../cache";
import type { StatisticalContext } from "./statistical";

describe("statistical anomaly detection", () => {
  const mockIsValkeyEnabled = vi.mocked(isValkeyEnabled);
  const mockRecordAndGetStats = vi.mocked(recordAndGetStats);

  beforeEach(() => {
    vi.clearAllMocks();
    // Set default environment
    process.env.STATISTICAL_SCORE_THRESHOLD = "0.01";
    process.env.STATISTICAL_DISTINCT_THRESHOLD = "50";
  });

  afterEach(() => {
    delete process.env.STATISTICAL_SCORE_THRESHOLD;
    delete process.env.STATISTICAL_DISTINCT_THRESHOLD;
  });

  describe("fetchStatisticalContext", () => {
    it("should return null when Valkey is disabled", async () => {
      mockIsValkeyEnabled.mockReturnValue(false);

      const result = await fetchStatisticalContext({
        user_agent: "Chrome/120",
        ja4: "t13d1516h2_abc",
      });

      expect(result).toBeNull();
      expect(mockRecordAndGetStats).not.toHaveBeenCalled();
    });

    it("should return null when user_agent is missing", async () => {
      mockIsValkeyEnabled.mockReturnValue(true);

      const result = await fetchStatisticalContext({
        ja4: "t13d1516h2_abc",
      });

      expect(result).toBeNull();
    });

    it("should return null when ja4 is missing", async () => {
      mockIsValkeyEnabled.mockReturnValue(true);

      const result = await fetchStatisticalContext({
        user_agent: "Chrome/120",
      });

      expect(result).toBeNull();
    });

    it("should fetch stats and compute score", async () => {
      mockIsValkeyEnabled.mockReturnValue(true);
      mockRecordAndGetStats.mockResolvedValue({
        total: 1000,
        comboCount: 5,
        distinct: 200,
      });

      const userAgent = "Mozilla/5.0 Chrome/120";
      const result = await fetchStatisticalContext({
        user_agent: userAgent,
        ja4: "t13d1516h2_abc",
      });

      expect(result).not.toBeNull();
      // uaFamily is now the full user-agent string (matches ja4db approach)
      expect(result!.uaFamily).toBe(userAgent);
      expect(result!.ja4).toBe("t13d1516h2_abc");
      expect(result!.stats.total).toBe(1000);
      expect(result!.stats.comboCount).toBe(5);
      expect(result!.stats.distinct).toBe(200);
      // score = 5 / (1000/200) = 5/5 = 1.0
      expect(result!.score).toBe(1.0);
    });
  });

  describe("detectStatisticalAnomalies", () => {
    it("should return empty array when context is null", () => {
      const signals = detectStatisticalAnomalies(null);
      expect(signals).toEqual([]);
    });

    it("should return empty array when distinct < threshold", () => {
      const context: StatisticalContext = {
        uaFamily: "Chrome",
        ja4: "t13d1516h2_abc",
        stats: { total: 100, comboCount: 1, distinct: 10 }, // < 50 threshold
        score: 0.001,
      };

      const signals = detectStatisticalAnomalies(context);
      expect(signals).toEqual([]);
    });

    it("should return empty array when score >= threshold", () => {
      const context: StatisticalContext = {
        uaFamily: "Chrome",
        ja4: "t13d1516h2_abc",
        stats: { total: 1000, comboCount: 50, distinct: 100 },
        score: 0.5, // >= 0.01 threshold
      };

      const signals = detectStatisticalAnomalies(context);
      expect(signals).toEqual([]);
    });

    it("should detect rare combo when score < threshold and distinct >= minDistinct", () => {
      const context: StatisticalContext = {
        uaFamily: "Chrome",
        ja4: "t13d1516h2_rare",
        stats: { total: 10000, comboCount: 1, distinct: 200 },
        score: 0.002, // < 0.01 threshold
      };

      const signals = detectStatisticalAnomalies(context);

      expect(signals).toHaveLength(1);
      expect(signals[0].type).toBe("STATISTICAL");
      expect(signals[0].code).toBe("RARE_FINGERPRINT_COMBO");
      expect(signals[0].severity).toBeGreaterThan(0.5);
      expect(signals[0].severity).toBeLessThanOrEqual(0.9);
      expect(signals[0].evidence.fields).toContain("user_agent");
      expect(signals[0].evidence.fields).toContain("ja4");
    });

    it("should scale severity inversely with score", () => {
      // Lower score = higher severity
      const lowScoreContext: StatisticalContext = {
        uaFamily: "Chrome",
        ja4: "t13d1516h2_very_rare",
        stats: { total: 10000, comboCount: 1, distinct: 200 },
        score: 0.0001, // Very low
      };

      const medScoreContext: StatisticalContext = {
        uaFamily: "Chrome",
        ja4: "t13d1516h2_rare",
        stats: { total: 10000, comboCount: 1, distinct: 200 },
        score: 0.005, // Medium-low
      };

      const lowSignals = detectStatisticalAnomalies(lowScoreContext);
      const medSignals = detectStatisticalAnomalies(medScoreContext);

      expect(lowSignals[0].severity).toBeGreaterThan(medSignals[0].severity);
    });
  });
});
