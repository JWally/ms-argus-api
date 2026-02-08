import { describe, it, expect } from "vitest";
import {
  FINGERPRINT_DEFINITIONS,
  getFingerprintTypes,
  getGroupingStrategy,
  COMBINED_THRESHOLD,
  COMBINED_MIN_CONFIDENCE,
  COMBINED_MIN_SCORE,
} from "./fingerprint-analysis";

describe("getFingerprintTypes", () => {
  it("should return all defined fingerprint type keys", () => {
    const types = getFingerprintTypes();
    expect(types).toContain("ja4");
    expect(types).toContain("h2");
    expect(types).toContain("maths");
    expect(types).toContain("fonts");
    expect(types).toContain("lies");
    expect(types).toContain("css");
    expect(types).toContain("tcp_mss");
    expect(types.length).toBeGreaterThanOrEqual(7);
  });

  it("should match Object.keys of FINGERPRINT_DEFINITIONS", () => {
    const types = getFingerprintTypes();
    expect(types).toEqual(Object.keys(FINGERPRINT_DEFINITIONS));
  });
});

describe("getGroupingStrategy", () => {
  it("should return configured groupBy for ja4", () => {
    const strategy = getGroupingStrategy("ja4");
    expect(Array.isArray(strategy)).toBe(true);
  });

  it("should return configured groupBy for h2", () => {
    const strategy = getGroupingStrategy("h2");
    expect(Array.isArray(strategy)).toBe(true);
  });

  it("should return default 'uaFamily' for unknown types", () => {
    const strategy = getGroupingStrategy("nonexistent_type");
    expect(strategy).toBe("uaFamily");
  });

  it("should return composite groupBy including 'asn' for tcp_mss", () => {
    const strategy = getGroupingStrategy("tcp_mss");
    expect(Array.isArray(strategy)).toBe(true);
    expect(strategy).toContain("asn");
  });
});

describe("FINGERPRINT_DEFINITIONS validation", () => {
  it("all definitions should have required fields", () => {
    for (const [type, def] of Object.entries(FINGERPRINT_DEFINITIONS)) {
      expect(def.path, `${type}: missing path`).toBeTruthy();
      expect(def.anomalyCode, `${type}: missing anomalyCode`).toBeTruthy();
      expect(def.fieldName, `${type}: missing fieldName`).toBeTruthy();
      expect(
        typeof def.maxSurpriseBits,
        `${type}: maxSurpriseBits not number`,
      ).toBe("number");
      expect(
        typeof def.saturationThreshold,
        `${type}: saturationThreshold not number`,
      ).toBe("number");
      expect(
        typeof def.anomalyThreshold,
        `${type}: anomalyThreshold not number`,
      ).toBe("number");
      expect(
        typeof def.confidenceThreshold,
        `${type}: confidenceThreshold not number`,
      ).toBe("number");
    }
  });

  it("all anomaly codes should be uppercase SCREAMING_SNAKE_CASE strings", () => {
    for (const [type, def] of Object.entries(FINGERPRINT_DEFINITIONS)) {
      expect(
        /^[A-Z][A-Z0-9_]+$/.test(def.anomalyCode),
        `${type}: anomalyCode '${def.anomalyCode}' should be SCREAMING_SNAKE_CASE`,
      ).toBe(true);
    }
  });

  it("all thresholds should be in valid ranges", () => {
    for (const [type, def] of Object.entries(FINGERPRINT_DEFINITIONS)) {
      expect(
        def.maxSurpriseBits,
        `${type}: maxSurpriseBits should be > 0`,
      ).toBeGreaterThan(0);
      expect(
        def.saturationThreshold,
        `${type}: saturationThreshold should be > 0`,
      ).toBeGreaterThan(0);
      expect(
        def.anomalyThreshold,
        `${type}: anomalyThreshold should be in [0,1]`,
      ).toBeGreaterThanOrEqual(0);
      expect(
        def.anomalyThreshold,
        `${type}: anomalyThreshold should be in [0,1]`,
      ).toBeLessThanOrEqual(1);
      expect(
        def.confidenceThreshold,
        `${type}: confidenceThreshold should be in [0,1]`,
      ).toBeGreaterThanOrEqual(0);
      expect(
        def.confidenceThreshold,
        `${type}: confidenceThreshold should be in [0,1]`,
      ).toBeLessThanOrEqual(1);
    }
  });

  it("transform functions should return string or null", () => {
    for (const [type, def] of Object.entries(FINGERPRINT_DEFINITIONS)) {
      if (def.transform) {
        // Test with null/undefined/invalid
        expect(def.transform(null)).toBeNull();
        expect(def.transform(undefined)).toBeNull();
        expect(def.transform("invalid")).toBeNull();

        // Test with valid numeric input for numeric transforms
        if (
          type === "tcp_mss" ||
          type === "css_key_count" ||
          type === "timing_resolution"
        ) {
          const result = def.transform(42);
          expect(
            typeof result === "string" || result === null,
            `${type}: transform should return string or null`,
          ).toBe(true);
        }
      }
    }
  });
});

describe("combined scoring constants", () => {
  it("COMBINED_THRESHOLD should be a number between 0 and 1", () => {
    expect(typeof COMBINED_THRESHOLD).toBe("number");
    expect(COMBINED_THRESHOLD).toBeGreaterThan(0);
    expect(COMBINED_THRESHOLD).toBeLessThanOrEqual(1);
  });

  it("COMBINED_MIN_CONFIDENCE should be a number between 0 and 1", () => {
    expect(typeof COMBINED_MIN_CONFIDENCE).toBe("number");
    expect(COMBINED_MIN_CONFIDENCE).toBeGreaterThan(0);
    expect(COMBINED_MIN_CONFIDENCE).toBeLessThanOrEqual(1);
  });

  it("COMBINED_MIN_SCORE should be a number between 0 and 1", () => {
    expect(typeof COMBINED_MIN_SCORE).toBe("number");
    expect(COMBINED_MIN_SCORE).toBeGreaterThan(0);
    expect(COMBINED_MIN_SCORE).toBeLessThanOrEqual(1);
  });
});
