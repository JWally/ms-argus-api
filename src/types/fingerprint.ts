// src/types/fingerprint.ts

/**
 * Fingerprint data from the client
 * Used by both matching and profile services
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
