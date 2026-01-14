// src/services/matching/types.ts
// AR-50: Re-export from central types for backwards compatibility
// AR-54: Added EvidenceCode export

export {
  // Base types
  Fingerprint,
  // Matching domain types
  SessionCacheValue,
  FingerprintPayload,
  MatchResult,
  Tier1IndexEntry,
  Tier2BucketEntry,
  // AR-54: Evidence codes
  EvidenceCode,
} from "../../types";

export type { EvidenceCode as EvidenceCodeType } from "../../types";
