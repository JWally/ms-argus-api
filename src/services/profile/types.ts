// src/services/profile/types.ts

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
 * Device flags for risk assessment
 */
export const DeviceFlags = {
  // Neutral signals
  NEW_DEVICE: "new_device",
  // Positive signals
  VERIFIED: "verified",
  RETURNING_USER: "returning_user",
  // Negative signals
  BOT_DETECTED: "bot_detected",
  HEADLESS_BROWSER: "headless_browser",
  FINGERPRINT_MISMATCH: "fingerprint_mismatch",
  RAPID_REQUESTS: "rapid_requests",
} as const;

export type DeviceFlag = (typeof DeviceFlags)[keyof typeof DeviceFlags];

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
