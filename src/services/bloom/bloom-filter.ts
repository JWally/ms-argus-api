// src/services/bloom/bloom-filter.ts
import type { Redis } from "ioredis";
import { FNV1A_OFFSET_BASIS, FNV1A_PRIME } from "../../helpers/constants";

/**
 * Configuration for the Bloom filter
 */
export interface BloomFilterConfig {
  /**
   * Expected number of items to store
   * Default: 10,000,000 (10M devices per tenant)
   */
  expectedItems?: number;

  /**
   * Target false positive rate
   * Default: 0.01 (1%)
   */
  falsePositiveRate?: number;

  /**
   * Key prefix for Redis
   * Default: "bf"
   */
  keyPrefix?: string;
}

/**
 * Default configuration values
 */
const DEFAULT_CONFIG: Required<BloomFilterConfig> = {
  expectedItems: 10_000_000,
  falsePositiveRate: 0.01,
  keyPrefix: "bf",
};

/**
 * Redis-backed Bloom filter for efficient negative lookups.
 *
 * Uses SETBIT/GETBIT for O(1) operations.
 * Implements multiple hash functions using FNV-1a with different seeds.
 *
 * Key format: {prefix}:{tenant}:{filter_type}
 * Example: bf:tenant-abc:stable_hash
 */
export class BloomFilter {
  private readonly redis: Redis;
  private readonly numBits: number;
  private readonly numHashFunctions: number;
  private readonly keyPrefix: string;

  constructor(redis: Redis, config: BloomFilterConfig = {}) {
    this.redis = redis;
    const mergedConfig = { ...DEFAULT_CONFIG, ...config };

    // Calculate optimal filter size
    // m = -(n * ln(p)) / (ln(2)^2)
    const { expectedItems, falsePositiveRate, keyPrefix } = mergedConfig;
    this.numBits = Math.ceil(
      (-expectedItems * Math.log(falsePositiveRate)) / Math.pow(Math.LN2, 2),
    );

    // Calculate optimal number of hash functions
    // k = (m/n) * ln(2)
    this.numHashFunctions = Math.ceil(
      (this.numBits / expectedItems) * Math.LN2,
    );

    this.keyPrefix = keyPrefix;
  }

  /**
   * Get the Redis key for a specific tenant and filter type
   */
  getKey(tenantId: string, filterType: string): string {
    return `${this.keyPrefix}:${tenantId}:${filterType}`;
  }

  /**
   * Get filter statistics for monitoring
   */
  getStats(): { numBits: number; numHashFunctions: number } {
    return {
      numBits: this.numBits,
      numHashFunctions: this.numHashFunctions,
    };
  }

  /**
   * Add an item to the bloom filter
   *
   * @param tenantId - Tenant identifier
   * @param filterType - Type of filter (e.g., "stable_hash")
   * @param value - Value to add
   */
  async add(
    tenantId: string,
    filterType: string,
    value: string,
  ): Promise<void> {
    const key = this.getKey(tenantId, filterType);
    const positions = this.getHashPositions(value);

    // Use pipeline for atomic batch operation
    const pipeline = this.redis.pipeline();
    for (const pos of positions) {
      pipeline.setbit(key, pos, 1);
    }
    await pipeline.exec();
  }

  /**
   * Check if an item might exist in the bloom filter
   *
   * @param tenantId - Tenant identifier
   * @param filterType - Type of filter (e.g., "stable_hash")
   * @param value - Value to check
   * @returns true if item might exist, false if definitely does not exist
   */
  async mightContain(
    tenantId: string,
    filterType: string,
    value: string,
  ): Promise<boolean> {
    const key = this.getKey(tenantId, filterType);
    const positions = this.getHashPositions(value);

    // Use pipeline for atomic batch operation
    const pipeline = this.redis.pipeline();
    for (const pos of positions) {
      pipeline.getbit(key, pos);
    }
    const results = await pipeline.exec();

    // If any bit is 0, the item definitely does not exist
    if (results) {
      for (const [err, bit] of results) {
        if (err) {
          // On error, assume item might exist (fail open)
          return true;
        }
        if (bit === 0) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Calculate hash positions for a value using multiple hash functions.
   * Uses double hashing technique: h(i) = h1 + i * h2
   *
   * @param value - Value to hash
   * @returns Array of bit positions
   */
  private getHashPositions(value: string): number[] {
    // Primary hash (FNV-1a)
    const h1 = this.fnv1a(value, 0);
    // Secondary hash (FNV-1a with different seed)
    const h2 = this.fnv1a(value, FNV1A_OFFSET_BASIS);

    const positions: number[] = [];
    for (let i = 0; i < this.numHashFunctions; i++) {
      // Double hashing: h(i) = (h1 + i * h2) mod m
      const pos = Math.abs((h1 + i * h2) % this.numBits);
      positions.push(pos);
    }
    return positions;
  }

  /**
   * FNV-1a hash implementation with configurable seed
   *
   * @param str - String to hash
   * @param seed - Optional seed value
   * @returns 32-bit hash as unsigned integer
   */
  private fnv1a(str: string, seed: number = 0): number {
    let hash = (FNV1A_OFFSET_BASIS ^ seed) >>> 0;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, FNV1A_PRIME);
    }
    return hash >>> 0;
  }
}
