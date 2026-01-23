// src/helpers/hash.test.ts
import { describe, it, expect } from "vitest";
import {
  fnv1a,
  fnv1aNum,
  hammingDistance,
  computeFuzzyMatchInfo,
} from "./hash";

describe("fnv1a", () => {
  // Known test vectors from FNV spec: http://www.isthe.com/chongo/tech/comp/fnv/
  it("should return offset basis for empty string", () => {
    // FNV1A_OFFSET_BASIS = 2166136261 = 0x811c9dc5
    expect(fnv1a("")).toBe("811c9dc5");
  });

  it('should hash "a" correctly', () => {
    // Known value: 0xe40c292c = 3826002220
    expect(fnv1a("a")).toBe("e40c292c");
  });

  it('should hash "abc" correctly', () => {
    // Known value: 0x1a47e90b = 440920331
    expect(fnv1a("abc")).toBe("1a47e90b");
  });

  it("should produce consistent hashes", () => {
    const input = "test-string-for-hashing";
    const hash1 = fnv1a(input);
    const hash2 = fnv1a(input);
    expect(hash1).toBe(hash2);
  });

  it("should produce different hashes for different inputs", () => {
    const hash1 = fnv1a("input1");
    const hash2 = fnv1a("input2");
    expect(hash1).not.toBe(hash2);
  });

  it("should handle unicode characters", () => {
    const hash = fnv1a("hello 世界");
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  it("should handle long strings", () => {
    const longString = "x".repeat(10000);
    const hash = fnv1a(longString);
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeLessThanOrEqual(8); // 32-bit hex
  });
});

describe("fnv1aNum", () => {
  it("should return offset basis for empty string", () => {
    expect(fnv1aNum("")).toBe(2166136261);
  });

  it('should hash "a" correctly', () => {
    expect(fnv1aNum("a")).toBe(3826002220);
  });

  it("should return a positive unsigned integer", () => {
    const hash = fnv1aNum("any string");
    expect(hash).toBeGreaterThanOrEqual(0);
    expect(hash).toBeLessThanOrEqual(0xffffffff);
  });
});

// AR-210: Tests for hammingDistance (consolidated from bucket-keys.ts to hash.ts)
describe("hammingDistance", () => {
  it("should return 0 for identical hashes", () => {
    expect(hammingDistance("0123456789abcdef", "0123456789abcdef")).toBe(0);
  });

  it("should return correct distance for known values", () => {
    // 0x000f vs 0x0000 in first 4 chars = 4 bits different (1111)
    expect(hammingDistance("000f000000000000", "0000000000000000")).toBe(4);
  });

  it("should return 64 for maximally different hashes", () => {
    expect(hammingDistance("ffffffffffffffff", "0000000000000000")).toBe(64);
  });

  it("should return -1 for invalid hex hashes", () => {
    expect(hammingDistance("not-a-hex-value!", "0000000000000000")).toBe(-1);
    expect(hammingDistance("0000000000000000", "xyz")).toBe(-1);
  });

  it("should handle 0x prefix", () => {
    expect(hammingDistance("0x0123456789abcdef", "0x0123456789abcdef")).toBe(0);
  });

  it("should be case-insensitive", () => {
    expect(hammingDistance("ABCDEF1234567890", "abcdef1234567890")).toBe(0);
  });
});

// AR-210: Tests for computeFuzzyMatchInfo (consolidated from tier modules to hash.ts)
describe("computeFuzzyMatchInfo", () => {
  it("should return correct hamming_distance and similarity for two valid hashes", () => {
    // 000f vs 0000 in first band = 4 bits different
    const result = computeFuzzyMatchInfo(
      "000f000000000000",
      "0000000000000000",
    );
    expect(result).toBeDefined();
    expect(result!.hamming_distance).toBe(4);
    expect(result!.similarity).toBeCloseTo(1 - 4 / 64, 5);
    expect(result!.incoming_hash).toBe("000f000000000000");
    expect(result!.stored_hash).toBe("0000000000000000");
  });

  it("should return distance 0 and similarity 1.0 for identical hashes", () => {
    const result = computeFuzzyMatchInfo(
      "abcdef1234567890",
      "abcdef1234567890",
    );
    expect(result).toBeDefined();
    expect(result!.hamming_distance).toBe(0);
    expect(result!.similarity).toBe(1);
  });

  it("should return correct values for known hamming distance", () => {
    // ffff vs 0000 in first 4 hex chars = 16 bits different
    const result = computeFuzzyMatchInfo(
      "ffff000000000000",
      "0000000000000000",
    );
    expect(result).toBeDefined();
    expect(result!.hamming_distance).toBe(16);
    expect(result!.similarity).toBeCloseTo(1 - 16 / 64, 5);
  });

  it("should return undefined when incomingHash is undefined", () => {
    const result = computeFuzzyMatchInfo(undefined, "0123456789abcdef");
    expect(result).toBeUndefined();
  });

  it("should return undefined when storedHash is undefined", () => {
    const result = computeFuzzyMatchInfo("0123456789abcdef", undefined);
    expect(result).toBeUndefined();
  });

  it("should return undefined when both hashes are undefined", () => {
    const result = computeFuzzyMatchInfo(undefined, undefined);
    expect(result).toBeUndefined();
  });
});
