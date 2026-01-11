// src/services/matching/types.ts

/**
 * Session cache value stored in Redis
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
 * Fingerprint data from the client
 */
export interface Fingerprint {
  stable_hash?: string;
  fuzzy_hash?: string;
  canvas_hash?: string;
  webgl_hash?: string;
  audio_hash?: string;
  ip_address?: string;
  ja4?: string;
  gpu_renderer?: string;
  screen_dims?: string;
  timezone?: string;
  evercookie_id?: string;
  // Bot detection signals
  user_agent?: string;
  hardware_concurrency?: number;
  device_memory?: number;
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
 * Device profile from DynamoDB
 */
export interface DeviceProfile {
  tenant_id: string;
  device_id: string;
  risk_score: number;
  flags: string[];
  first_seen_at?: number;
  last_seen_at?: number;
  request_count?: number;
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
