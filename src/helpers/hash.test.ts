import { describe, it, expect } from "vitest";
import { fnv1a, fnv1aNum, hammingDistance } from "./hash";

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

describe("hammingDistance", () => {
  describe("64-bit hashes (16 hex chars)", () => {
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

    it("should handle 0x prefix", () => {
      expect(hammingDistance("0x0123456789abcdef", "0x0123456789abcdef")).toBe(
        0,
      );
    });

    it("should be case-insensitive", () => {
      expect(hammingDistance("ABCDEF1234567890", "abcdef1234567890")).toBe(0);
    });
  });

  describe("256-bit hashes (64 hex chars)", () => {
    const zeros256 = "0".repeat(64);
    const ones256 = "f".repeat(64);
    const sample256 = "0123456789abcdef".repeat(4);

    it("should return 0 for identical 256-bit hashes", () => {
      expect(hammingDistance(sample256, sample256)).toBe(0);
    });

    it("should return 256 for maximally different 256-bit hashes", () => {
      expect(hammingDistance(ones256, zeros256)).toBe(256);
    });

    it("should return correct distance for known 256-bit values", () => {
      // First 4 chars differ: 000f vs 0000 = 4 bits
      const hash1 = "000f" + "0".repeat(60);
      const hash2 = zeros256;
      expect(hammingDistance(hash1, hash2)).toBe(4);
    });

    it("should handle 0x prefix for 256-bit hashes", () => {
      expect(hammingDistance("0x" + sample256, "0x" + sample256)).toBe(0);
    });
  });

  describe("invalid inputs", () => {
    it("should return -1 for invalid hex hashes", () => {
      expect(hammingDistance("not-a-hex-value!", "0000000000000000")).toBe(-1);
      expect(hammingDistance("0000000000000000", "xyz")).toBe(-1);
    });

    it("should return -1 for mismatched lengths", () => {
      expect(hammingDistance("0123456789abcdef", "0".repeat(64))).toBe(-1);
    });

    it("should return -1 for unsupported lengths", () => {
      // 32 chars (128 bits) not supported
      expect(hammingDistance("0".repeat(32), "0".repeat(32))).toBe(-1);
    });
  });
});
