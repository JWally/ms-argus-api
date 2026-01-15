// src/types/profile.ts
// AR-50: Consolidated profile domain types

import type { Fingerprint } from "./fingerprint";
import type { SigintData } from "./matching";

/**
 * Profile update payload from matching worker (via SQS)
 */
export interface ProfileUpdatePayload {
  tenant_id: string;
  device_id: string;
  fingerprint: Fingerprint;
  /** AR-81: Sigint data from ms-argus-web */
  sigint?: SigintData;
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
  // AR-64: Cryptographic device identity (ECDSA P-256 public key, Base64 SPKI)
  public_key?: string;
  // AR-65: Privacy browser detection
  privacy_browser?: string;
  is_private_browsing?: boolean;
  // AR-65: Bot detection signals
  bot_hash?: string;
  lie_count?: number;
  is_headless?: boolean;
  // AR-65: Network signals
  ja3?: string;
  tcp_rtt_us?: number;
  proxy_score?: number;
  vpn_score?: number;
  first_seen_at: number;
  last_seen_at: number;
  request_count: number;
  risk_score: number;
  flags: string[];
  updated_at: number;
  ttl: number;
}
