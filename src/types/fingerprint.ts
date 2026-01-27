/**
 * @fileoverview Core fingerprint type definition.
 * Defines the structure of browser/device fingerprint data collected from clients.
 * @module types/fingerprint
 */

/**
 * Fingerprint data collected from a client browser or device.
 *
 * Contains multiple signals used for device identification across the matching tiers:
 * - **Hashes**: Stable, fuzzy, canvas, WebGL, audio - for hash-based matching
 * - **Network**: IP, JA3/JA4 TLS fingerprints, RTT, proxy/VPN scores
 * - **Identity**: Public key, evercookie, sigint ID, favicon cache ID
 * - **Privacy**: Privacy browser detection, incognito mode
 * - **Structural**: Engine-level signals that can't be randomized
 *
 * Used by both matching services (to identify devices) and profile services
 * (to track device characteristics over time).
 *
 * @interface Fingerprint
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
  // Third-party cookie ID from CloudFront edge (sigint service)
  // Cross-site persistent identifier - survives first-party cookie clearing
  // Set by id.argus.pw CloudFront function with SameSite=None
  sigint_id?: string;
  // Favicon cache ID - persistent identifier stored via browser cache API
  favicon_cache_id?: string;
  // Cryptographic device identity (ECDSA P-256 public key, Base64 SPKI)
  // Near-perfect identifier - if present and matches, confidence 0.99
  public_key?: string;

  // Values: "brave", "firefox_rfp", "tor", "extension_detected", or undefined
  privacy_browser?: string;
  // True if browser is in private/incognito mode
  is_private_browsing?: boolean;

  user_agent?: string;
  hardware_concurrency?: number;
  device_memory?: number;
  // Hash of combined bot detection signals for matching
  bot_hash?: string;
  // Number of detected inconsistencies (navigator lies, etc.)
  lie_count?: number;
  // True if headless browser detected (Puppeteer, Playwright, etc.)
  is_headless?: boolean;

  // JA3 TLS fingerprint (older, less specific than JA4)
  ja3?: string;
  // TCP RTT in microseconds (network proximity signal)
  tcp_rtt_us?: number;
  // Probability of proxy usage (0-1)
  proxy_score?: number;
  // Probability of VPN usage (0-1)
  vpn_score?: number;
  // STUN/WebRTC discovered IPs
  stun_public_ip?: string;
  stun_local_ip?: string;
  // Autonomous System Number (network identity signal)
  asn?: number;
  // Timezone offset in minutes from UTC
  timezone_offset?: number;
  // TCP tuning parameters (network fingerprint)
  snd_mss?: number;
  pmtu?: number;

  // Structural fingerprint signals: stable "structural anchors" based on browser
  // engine internals that cannot be randomized without breaking website functionality.
  // Useful for tier2 matching when canvas/audio are blocked (e.g., Brave).

  // Math library fingerprint (FPU-level signal, very stable)
  maths_hash?: string;
  // Window API features (engine-level, stable across resets)
  window_features_hash?: string;
  // HTML element version/capabilities (engine-level)
  html_element_hash?: string;
  // CSS feature detection (browser-specific, stable)
  css_hash?: string;
  // Browser feature flags/capabilities
  features_hash?: string;
  // SVG rendering capabilities
  svg_hash?: string;
  // DOM clientRects rendering fingerprint
  client_rects_hash?: string;
  // Intl/locale settings hash
  intl_hash?: string;
  // Console error behavior hash
  console_errors_hash?: string;
  // WebGL extension count (capability signal)
  webgl_extensions_count?: number;
}
