/**
 * Semantic constants for matching tiers.
 *
 * Provides named constants for tier values used throughout the matching pipeline.
 * Numeric values are preserved for backward compatibility with metrics and logs.
 *
 * @module types/matching-tiers
 */

/**
 * Matching tier constants.
 *
 * - CACHE (0): Session cache hit - no matching needed
 * - IDENTITY (0.5): Identity match via public key, evercookie, or sigint ID
 * - HASH (1): Strong hash match via stable_hash or fuzzy_hash
 * - SIMHASH (1.5): SimHash LSH match for drift detection
 * - VECTOR (2): Vector similarity match via Qdrant
 * - NEW_DEVICE (-1): No match found, new device created
 */
export const MatchTier = {
  CACHE: 0,
  IDENTITY: 0.5,
  HASH: 1,
  SIMHASH: 1.5,
  VECTOR: 2,
  NEW_DEVICE: -1,
} as const;

export type MatchTierValue = (typeof MatchTier)[keyof typeof MatchTier];
