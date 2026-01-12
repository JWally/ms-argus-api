// src/helpers/hash.test.ts
import { describe, it, expect } from "vitest";
import { fnv1a, fnv1aNum } from "./hash";

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
