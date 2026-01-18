// src/services/matching/types.ts
// AR-50: Re-export from central types for backwards compatibility
// AR-54: Added EvidenceCode export
// AR-148: Added SessionAnomalySignal export

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
  // AR-148: Anomaly signals
  SessionAnomalySignal,
} from "../../types";

export type { EvidenceCode as EvidenceCodeType } from "../../types";
export type { SessionAnomalySignal as SessionAnomalySignalType } from "../../types";
