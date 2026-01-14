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
  // AR-64: Cryptographic device identity (ECDSA P-256 public key, Base64 SPKI)
  // Near-perfect identifier - if present and matches, confidence 0.99
  public_key?: string;

  // AR-65: Privacy browser detection
  // Values: "brave", "firefox_rfp", "tor", "extension_detected", or undefined
  privacy_browser?: string;
  // True if browser is in private/incognito mode
  is_private_browsing?: boolean;

  // AR-65: Bot detection signals
  user_agent?: string;
  hardware_concurrency?: number;
  device_memory?: number;
  // Hash of combined bot detection signals for matching
  bot_hash?: string;
  // Number of detected inconsistencies (navigator lies, etc.)
  lie_count?: number;
  // True if headless browser detected (Puppeteer, Playwright, etc.)
  is_headless?: boolean;

  // AR-65: Network signals (from sigint)
  // JA3 TLS fingerprint (older, less specific than JA4)
  ja3?: string;
  // TCP RTT in microseconds (network proximity signal)
  tcp_rtt_us?: number;
  // Probability of proxy usage (0-1)
  proxy_score?: number;
  // Probability of VPN usage (0-1)
  vpn_score?: number;
}
