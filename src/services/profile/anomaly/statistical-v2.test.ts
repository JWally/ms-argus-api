import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  computeShannonScore,
  computeConfidence,
  computeBlendedScore,
  computeCombinedScore,
  detectStatisticalAnomaliesV2,
  fetchStatisticalContextV2,
  type StatisticalContextV2,
  type FingerprintScore,
} from "./statistical-v2";
import type { FingerprintDefinition } from "../../../config/fingerprint-analysis";

// Mock valkey-client
vi.mock("../../cache", () => ({
  recordFingerprintV2: vi.fn(),
  fetchStatisticalV2Data: vi.fn(),
  isStatisticalV2Enabled: vi.fn(),
}));

import { recordFingerprintV2, isStatisticalV2Enabled } from "../../cache";

const mockRecordFingerprintV2 = recordFingerprintV2 as ReturnType<typeof vi.fn>;
const mockIsStatisticalV2Enabled = isStatisticalV2Enabled as ReturnType<
  typeof vi.fn
>;

// Helper to create valid FingerprintScore
function createScore(
  type: string,
  score: number,
  confidence: number,
  overrides: Partial<FingerprintScore> = {},
): FingerprintScore {
  return {
    type,
    groupingKey: "chrome",
    score,
    confidence,
    rawUaScore: score,
    rawGlobalScore: score * 0.8,
    uaTotal: 500,
    globalTotal: 10000,
    uaCount: 10,
    globalCount: 100,
    adequateSample: confidence >= 0.5,
    ...overrides,
  };
}

// Helper to create a test fingerprint definition
function createDefinition(
  overrides: Partial<FingerprintDefinition> = {},
): FingerprintDefinition {
  return {
    path: "test.path",
    anomalyCode: "TEST_CODE",
    fieldName: "test_field",
    maxSurpriseBits: 12,
    saturationThreshold: 500,
    anomalyThreshold: 0.6,
    confidenceThreshold: 0.5,
    ...overrides,
  };
}

describe("statistical-v2", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsStatisticalV2Enabled.mockReturnValue(true);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("computeShannonScore", () => {
    const MAX_BITS = 12; // Default for tests

    it("returns 0.5 for neutral case (no data)", () => {
      expect(computeShannonScore(0, 0, MAX_BITS)).toBe(0.5);
    });

    it("returns 1.0 for maximum surprise (unseen value)", () => {
      expect(computeShannonScore(0, 1000, MAX_BITS)).toBe(1.0);
    });

    it("returns ~0.083 for 50% probability with 12-bit ceiling", () => {
      // 50% → 1 bit surprise → 1/12 = 0.083
      const score = computeShannonScore(500, 1000, MAX_BITS);
      expect(score).toBeCloseTo(0.083, 2);
    });

    it("returns ~0.55 for 1% probability with 12-bit ceiling", () => {
      // 1% → ~6.64 bits → 6.64/12 ≈ 0.55
      const score = computeShannonScore(10, 1000, MAX_BITS);
      expect(score).toBeCloseTo(0.55, 1);
    });

    it("scales with different maxBits ceilings", () => {
      // Same probability but different ceilings
      const score10 = computeShannonScore(10, 1000, 10); // 6.64/10 = 0.664
      const score14 = computeShannonScore(10, 1000, 14); // 6.64/14 = 0.474
      expect(score10).toBeGreaterThan(score14);
    });

    it("caps at 1.0 for extremely rare events", () => {
      const score = computeShannonScore(1, 1_000_000, MAX_BITS);
      expect(score).toBe(1.0);
    });
  });

  describe("computeConfidence", () => {
    it("returns 0 for no samples", () => {
      expect(computeConfidence(0, 500)).toBe(0);
    });

    it("returns 1.0 for saturation threshold", () => {
      expect(computeConfidence(500, 500)).toBe(1.0);
      expect(computeConfidence(2000, 2000)).toBe(1.0);
    });

    it("returns 0.5 at 25% of saturation (sqrt curve)", () => {
      // sqrt(125/500) = sqrt(0.25) = 0.5
      expect(computeConfidence(125, 500)).toBe(0.5);
      expect(computeConfidence(500, 2000)).toBe(0.5);
    });

    it("caps at 1.0 for high sample counts", () => {
      expect(computeConfidence(1000, 500)).toBe(1.0);
    });
  });

  describe("computeBlendedScore", () => {
    const definition = createDefinition({
      maxSurpriseBits: 12,
      saturationThreshold: 500,
    });

    it("scores from UA baseline only, even with no UA samples", () => {
      const result = computeBlendedScore({
        uaCount: 0,
        uaTotal: 0,
        globalCount: 100,
        globalTotal: 1000,
        definition,
      });
      expect(result.confidence).toBe(0);
      expect(result.score).toBeCloseTo(result.rawUaScore, 3);
      expect(result.adequateSample).toBe(false);
    });

    it("scores from UA baseline at saturation", () => {
      const result = computeBlendedScore({
        uaCount: 50,
        uaTotal: 500,
        globalCount: 100,
        globalTotal: 1000,
        definition,
      });
      expect(result.confidence).toBe(1.0);
      expect(result.score).toBeCloseTo(result.rawUaScore, 3);
      expect(result.adequateSample).toBe(true);
    });

    it("marks adequate_sample true at 50% confidence (25% of saturation)", () => {
      const result = computeBlendedScore({
        uaCount: 10,
        uaTotal: 125,
        globalCount: 100,
        globalTotal: 1000,
        definition,
      });
      expect(result.confidence).toBe(0.5);
      expect(result.score).toBeCloseTo(result.rawUaScore, 3);
      expect(result.adequateSample).toBe(true);
    });

    it("marks adequate_sample false below 50% confidence", () => {
      const result = computeBlendedScore({
        uaCount: 5,
        uaTotal: 50,
        globalCount: 100,
        globalTotal: 1000,
        definition,
      });
      expect(result.confidence).toBeLessThan(0.5);
      expect(result.adequateSample).toBe(false);
    });
  });

  describe("computeCombinedScore", () => {
    it("returns null when less than 2 valid signals", () => {
      expect(computeCombinedScore([null, null], 0.3)).toBeNull();
      expect(
        computeCombinedScore([createScore("ja4", 0.5, 0.8)], 0.3),
      ).toBeNull();
    });

    it("returns null when signals below confidence threshold", () => {
      const lowConfidence = createScore("ja4", 0.5, 0.2); // Below 0.3 threshold
      const highConfidence = createScore("h2", 0.5, 0.8);
      expect(
        computeCombinedScore([lowConfidence, highConfidence], 0.3),
      ).toBeNull();
    });

    it("computes confidence-weighted mean for two equal-confidence signals", () => {
      const ja4 = createScore("ja4", 0.5, 0.8);
      const h2 = createScore("h2", 0.5, 0.8);
      // weighted mean = (0.5*0.8 + 0.5*0.8) / (0.8 + 0.8) = 0.8 / 1.6 = 0.5
      expect(computeCombinedScore([ja4, h2], 0.3)).toBeCloseTo(0.5, 3);
    });

    it("weights higher-confidence signals more", () => {
      const ja4 = createScore("ja4", 0.8, 1.0); // high confidence
      const h2 = createScore("h2", 0.2, 0.4); // low confidence
      // weighted mean = (0.8*1.0 + 0.2*0.4) / (1.0 + 0.4) = 0.88 / 1.4 ≈ 0.629
      expect(computeCombinedScore([ja4, h2], 0.3)).toBeCloseTo(0.629, 2);
    });

    it("handles one strong and one weak signal", () => {
      const ja4 = createScore("ja4", 0.8, 0.8);
      const h2 = createScore("h2", 0.0, 0.8);
      // h2 score=0.0 is below minScore (0.15), so only ja4 remains → null (< 2 signals)
      expect(computeCombinedScore([ja4, h2], 0.3)).toBeNull();
    });

    it("excludes signals below minimum score threshold", () => {
      const ja4 = createScore("ja4", 0.5, 0.8);
      const h2 = createScore("h2", 0.1, 0.8); // Below default minScore (0.15)
      // Only ja4 qualifies → null (< 2 signals)
      expect(computeCombinedScore([ja4, h2], 0.3)).toBeNull();
    });

    it("includes signals at or above minimum score threshold", () => {
      const ja4 = createScore("ja4", 0.5, 0.8);
      const h2 = createScore("h2", 0.2, 0.8); // Above minScore (0.15)
      // weighted mean = (0.5*0.8 + 0.2*0.8) / (0.8 + 0.8) = 0.56 / 1.6 = 0.35
      expect(computeCombinedScore([ja4, h2], 0.3)).toBeCloseTo(0.35, 3);
    });

    it("respects custom minScore parameter", () => {
      const ja4 = createScore("ja4", 0.5, 0.8);
      const h2 = createScore("h2", 0.3, 0.8);
      // With minScore=0.4, only ja4 qualifies → null
      expect(computeCombinedScore([ja4, h2], 0.3, 0.4)).toBeNull();
      // With minScore=0.1, both qualify → (0.5*0.8 + 0.3*0.8) / (0.8+0.8) = 0.64/1.6 = 0.4
      expect(computeCombinedScore([ja4, h2], 0.3, 0.1)).toBeCloseTo(0.4, 3);
    });

    it("stays in meaningful range with many moderate signals", () => {
      // 10 signals all scoring 0.3 with confidence 0.8
      const scores = Array.from({ length: 10 }, (_, i) =>
        createScore(`sig${i}`, 0.3, 0.8),
      );
      // weighted mean = (10 * 0.3 * 0.8) / (10 * 0.8) = 0.3
      expect(computeCombinedScore(scores, 0.3)).toBeCloseTo(0.3, 3);
    });
  });

  describe("detectStatisticalAnomaliesV2", () => {
    it("returns empty array for null context", () => {
      const signals = detectStatisticalAnomaliesV2(null);
      expect(signals).toHaveLength(0);
    });

    it("returns empty array when scores below threshold", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          ja4: "t13d1516h2_8daaf6152771",
          h2: "akamai",
        },
        groupingKeys: { ja4: "chrome", h2: "chrome" },
        scores: {
          ja4: createScore("ja4", 0.3, 0.8), // Below JA4 threshold (0.7)
          h2: createScore("h2", 0.3, 0.8), // Below H2 threshold (0.5)
        },
        combinedScore: null,
      };

      const signals = detectStatisticalAnomaliesV2(context);
      expect(signals).toHaveLength(0);
    });

    it("returns RARE_JA4_FOR_UA signal when JA4 score exceeds threshold", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          ja4: "t13d1516h2_rare_fingerprint",
          h2: null,
        },
        groupingKeys: { ja4: "chrome", h2: "chrome" },
        scores: {
          ja4: createScore("ja4", 0.75, 0.5), // Above 0.7 threshold, above 0.4 confidence
          h2: null,
        },
        combinedScore: null,
      };

      const signals = detectStatisticalAnomaliesV2(context);
      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe("RARE_JA4_FOR_UA");
      expect(signals[0].type).toBe("STATISTICAL");
      expect(signals[0].severity).toBe(0.75);
    });

    it("returns RARE_H2_FOR_UA signal when H2 score exceeds threshold", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "firefox",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Firefox/147",
        fingerprints: {
          ja4: null,
          h2: "rare_h2_fp",
        },
        groupingKeys: { ja4: "firefox", h2: "firefox" },
        scores: {
          ja4: null,
          h2: createScore("h2", 0.6, 0.5, {
            uaCount: 10,
            uaTotal: 500,
            globalCount: 100,
            globalTotal: 10000,
            groupingKey: "firefox",
          }), // Above 0.5 threshold, above 0.3 confidence
        },
        combinedScore: null,
      };

      const signals = detectStatisticalAnomaliesV2(context);
      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe("RARE_H2_FOR_UA");
    });

    it("returns combined signal when both slightly anomalous", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          ja4: "ja4_value",
          h2: "h2_value",
        },
        groupingKeys: { ja4: "chrome", h2: "chrome" },
        scores: {
          ja4: createScore("ja4", 0.5, 0.5), // Below JA4 threshold (0.6)
          h2: createScore("h2", 0.35, 0.5), // Below H2 threshold (0.4)
        },
        combinedScore: 0.7, // Above combined threshold (0.65)
      };

      const signals = detectStatisticalAnomaliesV2(context);
      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe("RARE_FINGERPRINT_COMBO");
    });

    it("does not return combined signal when individual already flagged", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          ja4: "ja4_value",
          h2: "h2_value",
        },
        groupingKeys: { ja4: "chrome", h2: "chrome" },
        scores: {
          ja4: createScore("ja4", 0.8, 0.5), // Above threshold
          h2: createScore("h2", 0.3, 0.5),
        },
        combinedScore: 0.86, // Would flag, but JA4 already flagged
      };

      const signals = detectStatisticalAnomaliesV2(context);
      expect(signals).toHaveLength(1);
      expect(signals[0].code).toBe("RARE_JA4_FOR_UA");
    });
  });

  describe("fetchStatisticalContextV2", () => {
    it("returns null when detection is disabled", async () => {
      mockIsStatisticalV2Enabled.mockReturnValue(false);

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        { tlsFingerprint: { ja4: "test" } },
      );

      expect(result).toBeNull();
    });

    it("returns null when no user agent", async () => {
      const result = await fetchStatisticalContextV2({} as never, {
        tlsFingerprint: { ja4: "test" },
      });

      expect(result).toBeNull();
    });

    it("returns null when no fingerprints available", async () => {
      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        {},
      );

      expect(result).toBeNull();
    });

    it("groups by composite key (UA string + browser family)", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const testUA =
        "Mozilla/5.0 (Windows NT 10.0) Chrome/144.0.0.0 Safari/537.36";
      const result = await fetchStatisticalContextV2(
        { user_agent: testUA } as never,
        { tlsFingerprint: { ja4: "t13d1516h2_abc123" } },
      );

      expect(result).not.toBeNull();
      expect(result?.uaFamily).toBe("chrome"); // Family is still parsed for fallback
      expect(result?.originalUA).toContain("Chrome/144");
      // Composite key: "UA string:browser family" - catches UA spoofing
      expect(mockRecordFingerprintV2).toHaveBeenCalledWith(
        `${testUA}:chrome`,
        "ja4",
        "t13d1516h2_abc123",
      );
    });

    it("fetches both JA4 and H2 in parallel", async () => {
      mockRecordFingerprintV2.mockImplementation(async (_ua, type) => {
        if (type === "ja4") {
          return { count: 5, total: 400, globalCount: 50, globalTotal: 10000 };
        }
        return { count: 20, total: 600, globalCount: 200, globalTotal: 15000 };
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        {
          tlsFingerprint: { ja4: "ja4_value" },
          h2Probe: { h2_fingerprint: { fingerprint: "h2_value" } },
        },
      );

      expect(result).not.toBeNull();
      expect(result?.scores.ja4).not.toBeNull();
      expect(result?.scores.h2).not.toBeNull();
      expect(result?.combinedScore).not.toBeNull(); // Should compute combined
      expect(mockRecordFingerprintV2).toHaveBeenCalledTimes(2);
    });

    it("handles recordFingerprintV2 errors gracefully", async () => {
      mockRecordFingerprintV2.mockRejectedValue(new Error("Valkey error"));

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        { tlsFingerprint: { ja4: "test" } },
      );

      expect(result).toBeNull();
    });

    it("detects bots and groups them separately", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 1,
        total: 100,
        globalCount: 10,
        globalTotal: 1000,
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "curl/8.5.0" } as never,
        { tlsFingerprint: { ja4: "test" } },
      );

      expect(result).not.toBeNull();
      expect(result?.uaFamily).toBe("bot");
    });

    it("extracts hash-source fingerprints (maths, fonts, etc.)", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        {},
        undefined,
        { maths: "abc123", fonts: "def456" },
      );

      expect(result).not.toBeNull();
      expect(result?.fingerprints.maths).toBe("abc123");
      expect(result?.fingerprints.fonts).toBe("def456");
    });

    it("extracts device-source fingerprints", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        {},
        {
          workerScope: {
            language: "en-US",
            timezoneLocation: "America/New_York",
          },
        } as never,
      );

      expect(result).not.toBeNull();
      // lang_for_tz should have extracted workerScope.language
      expect(result?.fingerprints.lang_for_tz).toBe("en-US");
    });

    it("resolves composite grouping keys with ASN", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const testUA = "Mozilla/5.0 Chrome/120";
      const result = await fetchStatisticalContextV2(
        { user_agent: testUA } as never,
        {
          tlsFingerprint: { ja4: "test_ja4" },
          tcpProbe: { rtt_fingerprint: { snd_mss: 1460 } },
        } as never,
      );

      expect(result).not.toBeNull();
      // tcp_mss groupBy includes "asn" — but without ASN in network data, falls back
      expect(result?.groupingKeys.tcp_mss).toBeTruthy();
    });

    it("extracts fingerprints with transforms (tcp_mss)", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        {
          tcpProbe: { rtt_fingerprint: { snd_mss: 1460 } },
        } as never,
      );

      expect(result).not.toBeNull();
      // tcp_mss has a transform: rounds to string
      if (result?.fingerprints.tcp_mss) {
        expect(result.fingerprints.tcp_mss).toBe("1460");
      }
    });

    it("includes baseline skip info when rules match", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const result = await fetchStatisticalContextV2(
        {
          user_agent: "Mozilla/5.0 Chrome/120",
          lie_count: 100,
          is_headless: true,
        } as never,
        { tlsFingerprint: { ja4: "test" } },
        {
          navigator: { userAgent: "Chrome/120" },
        } as never,
      );

      expect(result).not.toBeNull();
      expect(result?.baselineSkipped).toBe(true);
      expect(result?.matchedRules?.length).toBeGreaterThan(0);
    });

    it("resolves userAgentParsed from device navigator", async () => {
      mockRecordFingerprintV2.mockResolvedValue({
        count: 10,
        total: 500,
        globalCount: 100,
        globalTotal: 10000,
      });

      const result = await fetchStatisticalContextV2(
        { user_agent: "Mozilla/5.0 Chrome/120" } as never,
        { tlsFingerprint: { ja4: "test_ja4" } },
        {
          navigator: { userAgentParsed: "Chrome 120 Brave" },
        } as never,
      );

      expect(result).not.toBeNull();
      expect(result?.userAgentParsed).toBe("Chrome 120 Brave");
    });
  });

  describe("checkFingerprintAnomaly (via detectStatisticalAnomaliesV2)", () => {
    it("returns null for unknown anomaly code (non-existent type)", () => {
      // Create context with a type that has no definition
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          nonexistent_type: "some_value",
        },
        groupingKeys: { nonexistent_type: "chrome" },
        scores: {
          nonexistent_type: createScore("nonexistent_type", 0.9, 0.9),
        },
        combinedScore: null,
      };

      const signals = detectStatisticalAnomaliesV2(context);
      // Should not crash, just return no signals for unknown type
      expect(signals).toHaveLength(0);
    });

    it("returns signals for multiple anomalous fingerprints", () => {
      const context: StatisticalContextV2 = {
        uaFamily: "chrome",
        userAgentParsed: null,
        originalUA: "Mozilla/5.0 Chrome/144",
        fingerprints: {
          ja4: "rare_ja4",
          h2: "rare_h2",
        },
        groupingKeys: { ja4: "chrome", h2: "chrome" },
        scores: {
          ja4: createScore("ja4", 0.8, 0.5), // Above ja4 threshold 0.6
          h2: createScore("h2", 0.6, 0.5), // Above h2 threshold 0.4
        },
        combinedScore: 0.92,
      };

      const signals = detectStatisticalAnomaliesV2(context);
      // Both should flag individually
      expect(signals.length).toBeGreaterThanOrEqual(2);
      const codes = signals.map((s) => s.code);
      expect(codes).toContain("RARE_JA4_FOR_UA");
      expect(codes).toContain("RARE_H2_FOR_UA");
    });
  });
});
