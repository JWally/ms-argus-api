/**
 * Profile service types.
 *
 * Type definitions for profile updates and device storage.
 * @module
 */
import type { Fingerprint } from "./fingerprint";
import type { SigintData } from "./matching";

/** Profile update payload from matching worker (via SQS). */
export interface ProfileUpdatePayload {
  /** Device ID to update */
  device_id: string;
  /** Normalized fingerprint data */
  fingerprint: Fingerprint;
  /** Raw fingerprint for cross-field anomaly detection */
  raw_fingerprint?: unknown;
  /** Sigint data from ms-argus-web */
  sigint?: SigintData;
  /** Raw TCP probe blob for future analysis */
  tcp_blob?: string;
  /** Raw TLS fingerprint blob for future analysis */
  tls_blob?: string;
  /** Request timestamp (epoch ms) */
  timestamp: number;
  /** True if this is a newly created device */
  is_new_device?: boolean;
  /** Match tier for tier-gated identity association */
  match_tier?: number;
  /** Evidence codes indicating how the match was made */
  evidence_codes?: string[];
}

/** Single entry in the IP history ring buffer */
export interface IpHistoryEntry {
  /** IP address */
  ip: string;
  /** Autonomous System Number */
  asn: number;
  /** Last seen timestamp (epoch ms) */
  ts: number;
}

/** Device profile stored in DynamoDB. */
export interface DeviceProfile {
  /** Unique device identifier (UUID) */
  device_id: string;
  /** Stable fingerprint hash for tier-1 exact matching */
  stable_hash?: string;
  /** SimHash fuzzy hash for tier-1.5 LSH matching */
  fuzzy_hash?: string;
  /** Canvas fingerprint hash */
  canvas_hash?: string;
  /** WebGL fingerprint hash */
  webgl_hash?: string;
  /** AudioContext fingerprint hash */
  audio_hash?: string;
  /** GPU renderer string */
  gpu_renderer?: string;
  /** Screen dimensions ("WxH") */
  screen_dims?: string;
  /** Timezone identifier */
  timezone?: string;
  /** Persistent evercookie identifier */
  evercookie_id?: string;
  /** Cryptographic device identity (ECDSA P-256 public key, Base64 SPKI) */
  public_key?: string;
  /** Privacy browser detected (Brave, Tor, etc.) */
  privacy_browser?: string;
  /** True if private/incognito mode detected */
  is_private_browsing?: boolean;
  /** Bot detection hash */
  bot_hash?: string;
  /** Number of navigator lies detected */
  lie_count?: number;
  /** True if headless browser detected */
  is_headless?: boolean;
  /** JA3 TLS fingerprint */
  ja3?: string;
  /** TCP round-trip time in microseconds */
  tcp_rtt_us?: number;
  /** First seen timestamp (epoch ms) */
  first_seen_at: number;
  /** Last seen timestamp (epoch ms) */
  last_seen_at: number;
  /** Total request count for this device */
  request_count: number;
  /** Computed risk score (0.0 to 1.0) */
  risk_score: number;
  /** Risk flags array */
  flags: string[];
  /** Last profile update timestamp (epoch ms) */
  updated_at: number;
  /** TTL timestamp (epoch seconds) for DynamoDB expiration */
  ttl: number;
  /** Recent IP address history (newest-first, max 10 entries) */
  ip_history?: IpHistoryEntry[];
}
