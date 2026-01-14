// src/types/matching.ts
// AR-50: Consolidated matching domain types
// AR-54: Added evidence codes for match explainability

import type { Fingerprint } from "./fingerprint";

/**
 * Evidence codes explaining which signals contributed to a match decision.
 * Used for observability, debugging, and support escalations.
 */
export type EvidenceCode =
  | "EVERCOOKIE_MATCH" // T0.5: Matched on evercookie ID
  | "STABLE_HASH_MATCH" // T1: Matched on stable fingerprint hash
  | "FUZZY_HASH_MATCH" // T1: Matched on fuzzy fingerprint hash
  | "IP_JA4_BUCKET" // T2: Matched in IP+JA4 bucket
  | "GPU_SCREEN_TZ_BUCKET" // T2: Matched in GPU+Screen+Timezone bucket
  | "AUDIO_CANVAS_BUCKET" // T2: Matched in Audio+Canvas bucket
  | "NEW_DEVICE"; // No match found, new device created

/**
 * Session cache value stored in DynamoDB (AR-52: was Redis)
 */
export interface SessionCacheValue {
  status: "pending" | "complete" | "degraded";
  device_id: string;
  risk_score: number;
  confidence: number;
  match_tier: number;
  match_version: number;
  idempotency_key: string;
  flags: string[];
  evidence_codes: EvidenceCode[]; // AR-54: Which signals contributed to match
  updated_at: number;
}

/**
 * Fingerprint payload from SQS (sent by Go ingestion handler)
 */
export interface FingerprintPayload {
  session_id: string;
  tenant_id: string;
  fingerprint: Fingerprint;
  tcp_blob?: string;
  tls_blob?: string;
  headers: Record<string, string>;
  timestamp: number;
}

/**
 * Result of device matching
 */
export interface MatchResult {
  device_id: string;
  confidence: number;
  match_tier: number;
  is_new_device: boolean;
  risk_score: number;
  flags: string[];
  evidence_codes: EvidenceCode[]; // AR-54: Which signals contributed to match
}

/**
 * Tier 1 index entry
 */
export interface Tier1IndexEntry {
  tenant_id: string;
  hash_key: string;
  device_id: string;
  risk_score?: number;
  flags?: string[];
  ttl: number;
}

/**
 * Tier 2 bucket entry
 */
export interface Tier2BucketEntry {
  bucket_key: string;
  device_ids: string[];
  ttl: number;
}
