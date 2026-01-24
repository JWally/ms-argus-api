import type { Fingerprint } from "./fingerprint";
import type { SigintData } from "./matching";

/**
 * Profile update payload from matching worker (via SQS)
 */
export interface ProfileUpdatePayload {
  device_id: string;
  fingerprint: Fingerprint;
  /** Raw fingerprint for cross-field anomaly detection */
  raw_fingerprint?: unknown;
  /** Sigint data from ms-argus-web */
  sigint?: SigintData;
  tcp_blob?: string;
  tls_blob?: string;
  timestamp: number;
  is_new_device?: boolean;
  /** Match tier for tier-gated identity association */
  match_tier?: number;
  /** Evidence codes indicating how the match was made */
  evidence_codes?: string[];
}

/**
 * Device profile stored in DynamoDB
 */
export interface DeviceProfile {
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
  // Cryptographic device identity (ECDSA P-256 public key, Base64 SPKI)
  public_key?: string;
  privacy_browser?: string;
  is_private_browsing?: boolean;
  bot_hash?: string;
  lie_count?: number;
  is_headless?: boolean;
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
