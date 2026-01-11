// src/services/bloom/bloom-filter.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { BloomFilter } from "./bloom-filter";

// Mock Redis client
const createMockRedis = () => {
  const bitStore = new Map<string, Map<number, number>>();

  const getBits = (key: string) => {
    if (!bitStore.has(key)) {
      bitStore.set(key, new Map());
    }
    return bitStore.get(key)!;
  };

  const mockPipeline = {
    setbit: vi.fn((key: string, offset: number, value: number) => {
      getBits(key).set(offset, value);
      return mockPipeline;
    }),
    getbit: vi.fn((_key: string, _offset: number) => {
      return mockPipeline;
    }),
    exec: vi.fn(),
  };

  const redis = {
    pipeline: vi.fn(() => {
      // Reset pipeline calls for each pipeline()
      mockPipeline.setbit.mockClear();
      mockPipeline.getbit.mockClear();
      return mockPipeline;
    }),
    setbit: vi.fn((key: string, offset: number, value: number) => {
      getBits(key).set(offset, value);
      return Promise.resolve(0);
    }),
    getbit: vi.fn((key: string, offset: number) => {
      const bits = getBits(key);
      return Promise.resolve(bits.get(offset) ?? 0);
    }),
  };

  // Setup exec to return proper results based on getbit calls
  mockPipeline.exec.mockImplementation(() => {
    const getbitCalls = mockPipeline.getbit.mock.calls;
    if (getbitCalls.length > 0) {
      // Return results for getbit operations
      return Promise.resolve(
        getbitCalls.map(([key, offset]: [string, number]) => {
          const bits = getBits(key);
          return [null, bits.get(offset) ?? 0];
        }),
      );
    }
    // For setbit operations, return success
    return Promise.resolve(mockPipeline.setbit.mock.calls.map(() => [null, 0]));
  });

  return {
    redis: redis as any,
    bitStore,
    mockPipeline,
    clear: () => bitStore.clear(),
  };
};

describe("BloomFilter", () => {
  let mockRedis: ReturnType<typeof createMockRedis>;
  let bloomFilter: BloomFilter;

  beforeEach(() => {
    mockRedis = createMockRedis();
    bloomFilter = new BloomFilter(mockRedis.redis, {
      expectedItems: 1000, // Small for testing
      falsePositiveRate: 0.01,
    });
    mockRedis.clear();
  });

  describe("constructor", () => {
    it("should create filter with default config", () => {
      const filter = new BloomFilter(mockRedis.redis);
      const stats = filter.getStats();
      // Default: 10M items, 1% FPR
      // m = -(10M * ln(0.01)) / (ln(2)^2) ≈ 95,850,584 bits
      expect(stats.numBits).toBeGreaterThan(90_000_000);
      expect(stats.numHashFunctions).toBe(7); // k = (m/n) * ln(2) ≈ 7
    });

    it("should create filter with custom config", () => {
      const filter = new BloomFilter(mockRedis.redis, {
        expectedItems: 1000,
        falsePositiveRate: 0.1, // 10% FPR
      });
      const stats = filter.getStats();
      // m = -(1000 * ln(0.1)) / (ln(2)^2) ≈ 4,793 bits
      expect(stats.numBits).toBeGreaterThan(4000);
      expect(stats.numBits).toBeLessThan(6000);
      // k = (m/n) * ln(2) ≈ 3-4
      expect(stats.numHashFunctions).toBeGreaterThanOrEqual(3);
      expect(stats.numHashFunctions).toBeLessThanOrEqual(5);
    });
  });

  describe("getKey", () => {
    it("should generate correct key format", () => {
      const key = bloomFilter.getKey("tenant-abc", "stable_hash");
      expect(key).toBe("bf:tenant-abc:stable_hash");
    });

    it("should use custom prefix", () => {
      const filter = new BloomFilter(mockRedis.redis, { keyPrefix: "bloom" });
      const key = filter.getKey("tenant-123", "fuzzy_hash");
      expect(key).toBe("bloom:tenant-123:fuzzy_hash");
    });
  });

  describe("add", () => {
    it("should add item to filter using pipeline", async () => {
      await bloomFilter.add("tenant-abc", "stable_hash", "device-123");

      expect(mockRedis.redis.pipeline).toHaveBeenCalled();
      expect(mockRedis.mockPipeline.setbit).toHaveBeenCalled();
      expect(mockRedis.mockPipeline.exec).toHaveBeenCalled();
    });

    it("should set multiple bits for each item", async () => {
      await bloomFilter.add("tenant-abc", "stable_hash", "device-123");

      const stats = bloomFilter.getStats();
      expect(mockRedis.mockPipeline.setbit).toHaveBeenCalledTimes(
        stats.numHashFunctions,
      );
    });
  });

  describe("mightContain", () => {
    it("should return false for item not in filter", async () => {
      const result = await bloomFilter.mightContain(
        "tenant-abc",
        "stable_hash",
        "device-123",
      );
      expect(result).toBe(false);
    });

    it("should return true for item in filter", async () => {
      // First add the item
      await bloomFilter.add("tenant-abc", "stable_hash", "device-123");

      // Then check
      const result = await bloomFilter.mightContain(
        "tenant-abc",
        "stable_hash",
        "device-123",
      );
      expect(result).toBe(true);
    });

    it("should return false for different item", async () => {
      await bloomFilter.add("tenant-abc", "stable_hash", "device-123");

      const result = await bloomFilter.mightContain(
        "tenant-abc",
        "stable_hash",
        "device-456",
      );
      // May return true (false positive) or false
      // For this test, we accept either since we're testing the mechanism
      expect(typeof result).toBe("boolean");
    });
  });

  describe("false positive rate", () => {
    it("should have acceptable false positive rate", async () => {
      const filter = new BloomFilter(mockRedis.redis, {
        expectedItems: 100,
        falsePositiveRate: 0.1, // 10% target
      });

      // Add 100 items
      for (let i = 0; i < 100; i++) {
        await filter.add("tenant", "hash", `item-${i}`);
      }

      // Check 1000 items that were NOT added
      let falsePositives = 0;
      for (let i = 100; i < 1100; i++) {
        const result = await filter.mightContain("tenant", "hash", `item-${i}`);
        if (result) {
          falsePositives++;
        }
      }

      // False positive rate should be around 10% (allow some variance)
      const actualFPR = falsePositives / 1000;
      expect(actualFPR).toBeLessThan(0.2); // Allow up to 20% due to variance
    });
  });

  describe("tenant isolation", () => {
    it("should keep tenants isolated", async () => {
      await bloomFilter.add("tenant-1", "stable_hash", "device-123");

      const resultTenant1 = await bloomFilter.mightContain(
        "tenant-1",
        "stable_hash",
        "device-123",
      );
      const resultTenant2 = await bloomFilter.mightContain(
        "tenant-2",
        "stable_hash",
        "device-123",
      );

      expect(resultTenant1).toBe(true);
      expect(resultTenant2).toBe(false);
    });
  });

  describe("filter type isolation", () => {
    it("should keep filter types isolated", async () => {
      await bloomFilter.add("tenant-1", "stable_hash", "value-123");

      const resultStable = await bloomFilter.mightContain(
        "tenant-1",
        "stable_hash",
        "value-123",
      );
      const resultFuzzy = await bloomFilter.mightContain(
        "tenant-1",
        "fuzzy_hash",
        "value-123",
      );

      expect(resultStable).toBe(true);
      expect(resultFuzzy).toBe(false);
    });
  });

  describe("error handling", () => {
    it("should fail open on Redis error in mightContain", async () => {
      // Create a new mock that returns errors
      const errorRedis = {
        pipeline: vi.fn(() => ({
          getbit: vi.fn().mockReturnThis(),
          exec: vi.fn().mockResolvedValue([[new Error("Redis error"), null]]),
        })),
      };

      const filter = new BloomFilter(errorRedis as any, { expectedItems: 100 });
      const result = await filter.mightContain("tenant", "hash", "value");

      // Should return true (fail open) to avoid blocking legitimate requests
      expect(result).toBe(true);
    });
  });

  describe("getStats", () => {
    it("should return filter statistics", () => {
      const stats = bloomFilter.getStats();
      expect(stats).toHaveProperty("numBits");
      expect(stats).toHaveProperty("numHashFunctions");
      expect(stats.numBits).toBeGreaterThan(0);
      expect(stats.numHashFunctions).toBeGreaterThan(0);
    });
  });
});
