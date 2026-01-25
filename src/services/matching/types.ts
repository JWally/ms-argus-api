/**
 * @fileoverview Re-exports matching-related types from the main types module.
 * Provides convenient access to matching types within the services/matching module.
 * @module services/matching/types
 */

export {
  Fingerprint,
  SessionCacheValue,
  FingerprintPayload,
  MatchResult,
  Tier1IndexEntry,
  Tier2BucketEntry,
  EvidenceCode,
  SessionAnomalySignal,
  SimHashDetails,
  FuzzyMatchInfo,
} from "../../types";

export type { EvidenceCode as EvidenceCodeType } from "../../types";
export type { SessionAnomalySignal as SessionAnomalySignalType } from "../../types";
