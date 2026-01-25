import { FNV1A_OFFSET_BASIS, FNV1A_PRIME } from "./constants";
import type { FuzzyMatchInfo } from "../types/matching";

/**
 * FNV-1a 32-bit hash function.
 *
 * Standard implementation using Math.imul() for correct 32-bit multiplication.
 *
 * Known test vectors:
 * - fnv1a("") = 2166136261 (0x811c9dc5) - offset basis
 * - fnv1a("a") = 3826002220 (0xe40c292c)
 * - fnv1a("abc") = 440920331 (0x1a47e90b)
 *
 * @param str - String to hash
 * @returns 32-bit hash as hex string
 */
export function fnv1a(str: string): string {
  let hash = FNV1A_OFFSET_BASIS;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, FNV1A_PRIME);
  }
  return (hash >>> 0).toString(16);
}

/**
 * FNV-1a 32-bit hash function returning numeric value.
 *
 * Same as fnv1a() but returns a number instead of hex string.
 * Useful for cases where numeric hash is needed.
 *
 * @param str - String to hash
 * @returns 32-bit unsigned integer hash
 */
export function fnv1aNum(str: string): number {
  let hash = FNV1A_OFFSET_BASIS;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, FNV1A_PRIME);
  }
  return hash >>> 0;
}

/**
 * Calculate Hamming distance between two 64-bit hex hashes
 * Counts the number of differing bits between two SimHash values.
 *
 * @param hash1 - First hash as hex string
 * @param hash2 - Second hash as hex string
 * @returns Number of differing bits (0-64), or -1 if invalid
 */
export function hammingDistance(hash1: string, hash2: string): number {
  const h1 = hash1.replace(/^0x/i, "").toLowerCase();
  const h2 = hash2.replace(/^0x/i, "").toLowerCase();

  if (!/^[0-9a-f]{16}$/.test(h1) || !/^[0-9a-f]{16}$/.test(h2)) {
    return -1;
  }

  let distance = 0;

  // Process 4 chars (16 bits) at a time to stay within JS safe integer range
  for (let i = 0; i < 16; i += 4) {
    const chunk1 = parseInt(h1.slice(i, i + 4), 16);
    const chunk2 = parseInt(h2.slice(i, i + 4), 16);
    const xor = chunk1 ^ chunk2;
    // Count set bits (Brian Kernighan's algorithm)
    let bits = xor;
    while (bits) {
      distance++;
      bits &= bits - 1;
    }
  }

  return distance;
}

/**
 * Compute fuzzy match info for drift detection
 * Computes Hamming distance between incoming and stored fuzzy_hash
 * @param incomingHash - Incoming fuzzy hash from request
 * @param storedHash - Stored fuzzy hash from profile
 * @returns FuzzyMatchInfo if both hashes present, undefined otherwise
 */
export function computeFuzzyMatchInfo(
  incomingHash: string | undefined,
  storedHash: string | undefined,
): FuzzyMatchInfo | undefined {
  if (!incomingHash || !storedHash) {
    return undefined;
  }

  const distance = hammingDistance(incomingHash, storedHash);

  return {
    incoming_hash: incomingHash,
    stored_hash: storedHash,
    hamming_distance: distance,
    similarity: distance >= 0 ? 1 - distance / 64 : 0,
  };
}
