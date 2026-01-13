// src/types/matching.ts
// AR-50: Consolidated matching domain types

import type { Fingerprint } from "./fingerprint";

/**
 * Session cache value stored in DynamoDB
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
