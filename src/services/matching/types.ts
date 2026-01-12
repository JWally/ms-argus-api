// src/services/matching/types.ts
// AR-50: Re-export from central types for backwards compatibility

export {
  // Base types
  Fingerprint,
  // Matching domain types
  SessionCacheValue,
  FingerprintPayload,
  MatchResult,
  Tier1IndexEntry,
  Tier2BucketEntry,
} from "../../types";
