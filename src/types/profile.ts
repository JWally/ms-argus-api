// src/types/profile.ts
// AR-50: Consolidated profile domain types

import type { Fingerprint } from "./fingerprint";

/**
 * Profile update payload from matching worker (via SQS)
 */
export interface ProfileUpdatePayload {
  tenant_id: string;
  device_id: string;
  fingerprint: Fingerprint;
  tcp_blob?: string;
  tls_blob?: string;
  timestamp: number;
  is_new_device?: boolean;
}

/**
 * Device profile stored in DynamoDB
 */
export interface DeviceProfile {
  tenant_id: string;
  device_id: string;
  stable_hash?: string;
  fuzzy_hash?: string;
  canvas_hash?: string;
  webgl_hash?: string;
  audio_hash?: string;
  gpu_renderer?: string;
  screen_dims?: string;
  timezone?: string;
  evercookie_id?: string;
  first_seen_at: number;
  last_seen_at: number;
  request_count: number;
  risk_score: number;
  flags: string[];
  updated_at: number;
  ttl: number;
}
