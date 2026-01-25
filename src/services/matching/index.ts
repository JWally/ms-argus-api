/**
 * @fileoverview Matching service module exports.
 *
 * Provides device fingerprint matching across multiple tiers:
 * - **Tier 0**: Session cache lookup (instant, 100% confidence)
 * - **Tier 0.5**: Identity matching (public key, cookies, sigint ID)
 * - **Tier 1**: Hash-based matching (stable_hash exact match)
 * - **Tier 1.5**: SimHash fuzzy matching (fuzzy_hash locality-sensitive)
 * - **Tier 2**: Compound matching (UA/IP bucket + scoring)
 * - **Tier 3**: Vector similarity search (future, via Qdrant)
 *
 * @module services/matching
 */

export * from "./types";

export * from "./matching-service";

export {
  writeMatchResult,
  writeDegradedResult,
  type Tier0CacheDeps,
} from "./tier0-cache";

export {
  tier05PublicKeyLookup,
  tier05CookieLookup,
  tier05SigintIdLookup,
  type Tier05IdentityDeps,
} from "./tier05-identity";

export { tier1HashMatch, type Tier1HashDeps } from "./tier1-hash";

export { tier15SimHashMatch, type Tier15SimHashDeps } from "./tier15-simhash";

export {
  loadProfile,
  type ProfileLoaderDeps,
  type ProfileData,
} from "./profile-loader";

export {
  tier2CompoundMatch,
  tier2CompoundMatchWithTimeout,
  type Tier2CompoundDeps,
} from "./tier2-compound";

export {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  type SessionAnchorDeps,
} from "./session-anchors";

export {
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "../../helpers/bucket-keys";
