// src/services/matching/index.ts
// AR-119: Re-exports for backward compatibility after module split

// Types
export * from "./types";

// Main orchestration service
export * from "./matching-service";

// Tier 0: Session cache operations
export {
  checkCache,
  writeMatchResult,
  writeDegradedResult,
  type Tier0CacheDeps,
} from "./tier0-cache";

// Tier 0.5: Identity lookups (evercookie, sigint, public key)
export {
  tier05PublicKeyLookup,
  tier05CookieLookup,
  tier05SigintIdLookup,
  type Tier05IdentityDeps,
} from "./tier05-identity";

// Tier 1: Hash matching (stable, fuzzy)
export { tier1HashMatch, type Tier1HashDeps } from "./tier1-hash";

// AR-157: Shared profile loading
export {
  loadProfile,
  type ProfileLoaderDeps,
  type ProfileData,
} from "./profile-loader";

// Tier 2: Compound bucket matching with cardinality
export {
  tier2CompoundMatch,
  tier2CompoundMatchWithTimeout,
  type Tier2CompoundDeps,
} from "./tier2-compound";

// Session anchors: IP+UA and session anchor lookups
export {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
  type SessionAnchorDeps,
} from "./session-anchors";
