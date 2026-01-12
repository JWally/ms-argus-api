// src/helpers/hash.ts
// Single source of truth for hash functions (AR-32)

import { FNV1A_OFFSET_BASIS, FNV1A_PRIME } from "./constants";

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
