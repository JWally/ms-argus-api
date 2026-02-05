import { describe, it, expect, vi } from "vitest";

// Mock powertools
vi.mock("@aws-lambda-powertools/logger", () => ({
  Logger: vi.fn().mockImplementation(() => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  })),
}));

import {
  computeShannonScore,
  computeConfidence,
  computeBlendedScore,
  getBucket,
  extractDeviceType,
  TLS_RATIO_BUCKETS,
  MSS_BUCKETS,
  type NetworkBaselineContext,
} from "./network-baseline";

describe("network-baseline scoring", () => {
  describe("getBucket", () => {
    it("should return correct TLS ratio bucket", () => {
      expect(getBucket(0.3, TLS_RATIO_BUCKETS)).toBe("0.0-0.5");
      expect(getBucket(0.9, TLS_RATIO_BUCKETS)).toBe("0.8-1.0");
      expect(getBucket(1.1, TLS_RATIO_BUCKETS)).toBe("1.0-1.2");
      expect(getBucket(3.5, TLS_RATIO_BUCKETS)).toBe("3.0-5.0");
      expect(getBucket(15.0, TLS_RATIO_BUCKETS)).toBe("10.0+");
    });

    it("should return correct MSS bucket", () => {
      expect(getBucket(1100, MSS_BUCKETS)).toBe("0-1200");
      expect(getBucket(1350, MSS_BUCKETS)).toBe("1300-1400");
      expect(getBucket(1460, MSS_BUCKETS)).toBe("1450-1500");
      expect(getBucket(9000, MSS_BUCKETS)).toBe("1500+");
    });

    it("should return last bucket for values exceeding all", () => {
      expect(getBucket(100, TLS_RATIO_BUCKETS)).toBe("10.0+");
      expect(getBucket(5000, MSS_BUCKETS)).toBe("1500+");
    });
  });

  describe("extractDeviceType", () => {
    it("should detect mobile devices", () => {
      expect(
        extractDeviceType(
          "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        ),
      ).toBe("mobile");
      expect(
        extractDeviceType(
          "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36",
        ),
      ).toBe("mobile");
    });

    it("should detect tablets", () => {
      expect(
        extractDeviceType(
          "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
        ),
      ).toBe("tablet");
      expect(
        extractDeviceType(
          "Mozilla/5.0 (Linux; Android 12; SM-T870) Tablet AppleWebKit/537.36",
        ),
      ).toBe("tablet");
    });

    it("should default to desktop", () => {
      expect(
        extractDeviceType(
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ),
      ).toBe("desktop");
      expect(
        extractDeviceType(
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        ),
      ).toBe("desktop");
      expect(extractDeviceType(undefined)).toBe("desktop");
      expect(extractDeviceType("")).toBe("desktop");
    });
  });

  describe("computeShannonScore", () => {
    it("should return 0.5 (neutral) when no data", () => {
      expect(computeShannonScore(0, 0)).toBe(0.5);
    });

    it("should return 1.0 (max surprise) for unseen bucket", () => {
      expect(computeShannonScore(0, 1000)).toBe(1.0);
    });

    it("should return low score for common bucket", () => {
      // 50% probability = 1 bit surprise, normalized by 12 = 0.083
      const score = computeShannonScore(500, 1000);
      expect(score).toBeCloseTo(1 / 12, 2);
    });

    it("should return higher score for rare bucket", () => {
      // 1% probability = 6.6 bits surprise, normalized by 12 = 0.55
      const score = computeShannonScore(10, 1000);
      expect(score).toBeCloseTo(6.64 / 12, 2);
    });

    it("should cap at 1.0 for extremely rare events", () => {
      // 0.01% = 13.3 bits, exceeds MAX_SURPRISE_BITS of 12
      const score = computeShannonScore(1, 10000);
      expect(score).toBe(1.0);
    });

    it("should use fixed normalization for consistent cross-ASN scoring", () => {
      // 10% probability on small ASN
      const smallAsnScore = computeShannonScore(10, 100);
      // 10% probability on large ASN
      const largeAsnScore = computeShannonScore(100000, 1000000);
      // Both should have same score (~3.32 bits / 12 = 0.277)
      expect(smallAsnScore).toBeCloseTo(largeAsnScore, 3);
    });
  });

  describe("computeConfidence", () => {
    it("should return 0 for no samples", () => {
      expect(computeConfidence(0)).toBe(0);
    });

    it("should return 1.0 at saturation threshold", () => {
      expect(computeConfidence(500)).toBe(1.0);
    });

    it("should cap at 1.0 above threshold", () => {
      expect(computeConfidence(2000)).toBe(1.0);
    });

    it("should use sqrt curve for gradual increase", () => {
      // sqrt(125/500) = sqrt(0.25) = 0.5
      expect(computeConfidence(125)).toBeCloseTo(0.5, 3);
      // sqrt(80/500) = sqrt(0.16) = 0.4
      expect(computeConfidence(80)).toBeCloseTo(0.4, 3);
    });
  });

  describe("computeBlendedScore", () => {
    it("should use global score when ASN has no data (confidence=0)", () => {
      const asnCtx: NetworkBaselineContext = {
        asn: "12345",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map(),
          mss: new Map(),
        },
        total: 0, // No ASN data
      };

      const globalCtx: NetworkBaselineContext = {
        asn: "global",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map([["1.0-1.2", 5000]]),
          mss: new Map([["1400-1450", 5000]]),
        },
        total: 10000,
      };

      const result = computeBlendedScore(asnCtx, globalCtx);
      // With confidence=0, should be 100% global score
      expect(result.confidence).toBe(0);
      // Global has 50% in each bucket = low surprise
      expect(result.score).toBeLessThan(0.2);
    });

    it("should use ASN score when fully saturated (confidence=1)", () => {
      const asnCtx: NetworkBaselineContext = {
        asn: "12345",
        deviceType: "desktop",
        tlsRatioBucket: "5.0-10.0", // Rare bucket
        mssBucket: "0-1200", // Rare bucket (heavy tunnel)
        histograms: {
          tlsRatio: new Map([
            ["1.0-1.2", 450],
            ["5.0-10.0", 5],
          ]),
          mss: new Map([
            ["1400-1450", 450],
            ["0-1200", 5],
          ]),
        },
        total: 500, // Saturated
      };

      const globalCtx: NetworkBaselineContext = {
        asn: "global",
        deviceType: "desktop",
        tlsRatioBucket: "5.0-10.0",
        mssBucket: "0-1200",
        histograms: {
          tlsRatio: new Map([["5.0-10.0", 5000]]),
          mss: new Map([["0-1200", 5000]]),
        },
        total: 10000,
      };

      const result = computeBlendedScore(asnCtx, globalCtx);
      expect(result.confidence).toBe(1.0);
      // Should be high score (rare bucket for this ASN)
      expect(result.score).toBeGreaterThan(0.4);
    });

    it("should blend scores proportionally to confidence", () => {
      const asnCtx: NetworkBaselineContext = {
        asn: "12345",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map([["1.0-1.2", 60]]), // 50% = low surprise
          mss: new Map([["1400-1450", 60]]),
        },
        total: 125, // confidence = sqrt(125/500) = 0.5
      };

      const globalCtx: NetworkBaselineContext = {
        asn: "global",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map([["1.0-1.2", 100]]), // 1% = high surprise
          mss: new Map([["1400-1450", 100]]),
        },
        total: 10000,
      };

      const result = computeBlendedScore(asnCtx, globalCtx);
      expect(result.confidence).toBeCloseTo(0.5, 2);
      // Score should be blend of ASN (low) and global (high)
      expect(result.score).toBeGreaterThan(0.2);
      expect(result.score).toBeLessThan(0.6);
    });

    it("should include signals for high-confidence anomalies", () => {
      const asnCtx: NetworkBaselineContext = {
        asn: "AS7018",
        deviceType: "desktop",
        tlsRatioBucket: "10.0+",
        mssBucket: "0-1200",
        histograms: {
          tlsRatio: new Map([
            ["1.0-1.2", 490],
            ["10.0+", 1],
          ]),
          mss: new Map([
            ["1400-1450", 490],
            ["0-1200", 1],
          ]),
        },
        total: 500,
      };

      const globalCtx: NetworkBaselineContext = {
        asn: "global",
        deviceType: "desktop",
        tlsRatioBucket: "10.0+",
        mssBucket: "0-1200",
        histograms: {
          tlsRatio: new Map([
            ["1.0-1.2", 9900],
            ["10.0+", 10],
          ]),
          mss: new Map([
            ["1400-1450", 9900],
            ["0-1200", 10],
          ]),
        },
        total: 10000,
      };

      const result = computeBlendedScore(asnCtx, globalCtx);
      expect(result.score).toBeGreaterThan(0.5);
      expect(result.signals).toContain("high_confidence_asn_anomaly:AS7018");
      expect(result.signals).toContain("rare_tls_ratio_for_asn:10.0+");
    });

    it("should include metadata for debugging", () => {
      const asnCtx: NetworkBaselineContext = {
        asn: "12345",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map([["1.0-1.2", 250]]),
          mss: new Map([["1400-1450", 250]]),
        },
        total: 500,
      };

      const globalCtx: NetworkBaselineContext = {
        asn: "global",
        deviceType: "desktop",
        tlsRatioBucket: "1.0-1.2",
        mssBucket: "1400-1450",
        histograms: {
          tlsRatio: new Map([["1.0-1.2", 5000]]),
          mss: new Map([["1400-1450", 5000]]),
        },
        total: 10000,
      };

      const result = computeBlendedScore(asnCtx, globalCtx);
      expect(result.meta.asnTotal).toBe(500);
      expect(result.meta.globalTotal).toBe(10000);
      expect(result.meta.rawAsnScore).toBeDefined();
      expect(result.meta.rawGlobalScore).toBeDefined();
    });
  });
});
