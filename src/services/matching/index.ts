export * from "./types";

export * from "./matching-service";

export {
  checkCache,
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
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
  type SessionAnchorDeps,
} from "./session-anchors";
