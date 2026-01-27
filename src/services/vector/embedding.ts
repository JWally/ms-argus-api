/**
 * @fileoverview Fingerprint embedding service.
 *
 * Converts normalized fingerprint data into a 256-dimensional vector
 * suitable for similarity search in Qdrant.
 *
 * Embedding structure (v3 - improved for privacy browsers):
 * - Structural hashes (48 dims): htmlElement, maths, fonts, windowFeatures, css, svg
 * - Rendering (48 dims): canvas, webgl, audio, gpu - ZEROED for Brave/private
 * - Hardware (32 dims): concurrency, memory, screen, webgl extensions
 * - Network (32 dims): JA3/JA4, IP (8 dims preserving proximity), ASN (3 dims), TCP tuning
 * - Behavioral (22 dims): timezone, privacy flags, headless, lie count, features
 * - Identity (16 dims): stable hash, fuzzy hash
 * - Reserved (58 dims): future expansion
 *
 * Key improvements in v3:
 * - IP encoded as octets (preserves /24 subnet proximity in vector space)
 * - ASN encoded with log-normalization and RIR grouping
 * - Brave/private mode zeroes randomized canvas/audio/webgl signals
 * - JA3/JA4 encoded as bipolar hash (more stable than feature hash)
 *
 * @module services/vector/embedding
 */

import type { Fingerprint } from "../../types/fingerprint";

/**
 * Vector embedding result
 */
export interface EmbeddingResult {
  /** The vector embedding */
  vector: number[];
  /** Number of dimensions */
  dimensions: number;
  /** Version of the embedding schema (for future migrations) */
  version: number;
}

/**
 * Current embedding schema version.
 * Increment when the embedding structure changes significantly.
 *
 * v3: Improved IP/ASN encoding, Brave/private handling, JA3/JA4 as bipolar
 */
export const EMBEDDING_VERSION = 3;

/**
 * Expected number of dimensions for the current embedding version.
 */
export const EMBEDDING_DIMENSIONS = 256;

// ============================================================================
// ENCODING UTILITIES
// ============================================================================

/**
 * Normalize a numeric value to 0-1 range using min-max scaling.
 */
function normalize(
  value: number | undefined,
  min: number,
  max: number,
): number {
  if (value === undefined || value === null || isNaN(value)) return 0;
  const clamped = Math.max(min, Math.min(max, value));
  return (clamped - min) / (max - min);
}

/**
 * Convert a boolean or truthy value to 0 or 1.
 */
function boolToNum(value: unknown): number {
  return value ? 1 : 0;
}

/** Convert a single hex nibble to 4 bipolar values */
function nibbleToBipolar(nibble: number): [number, number, number, number] {
  return [
    (nibble >> 3) & 1 ? 1 : -1,
    (nibble >> 2) & 1 ? 1 : -1,
    (nibble >> 1) & 1 ? 1 : -1,
    nibble & 1 ? 1 : -1,
  ];
}

/**
 * Convert a hex hash string to a bipolar vector (+1/-1) for SimHash-style encoding.
 * Each hex character (4 bits) expands to 4 dimensions.
 */
function hashToBipolar(hash: string | undefined, dims: number): number[] {
  if (!hash) return new Array(dims).fill(0);

  const result: number[] = [];
  const maxChars = Math.min(hash.length, Math.ceil(dims / 4));

  for (let i = 0; i < maxChars; i++) {
    const nibble = parseInt(hash[i], 16);
    if (!isNaN(nibble)) {
      result.push(...nibbleToBipolar(nibble));
    }
  }

  // Pad or truncate to exact dims
  return result
    .slice(0, dims)
    .concat(new Array(Math.max(0, dims - result.length)).fill(0));
}

/**
 * Hash a string to a single normalized float (0-1).
 * Uses FNV-1a hash for good distribution.
 */
function stringToFloat(str: string | undefined): number {
  if (!str) return 0;
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) % 1000000) / 1000000;
}

/**
 * Hash a string to multiple dimensions using different seeds.
 * Creates a "feature hash" representation.
 */
function stringToVector(str: string | undefined, dims: number): number[] {
  const result: number[] = new Array(dims).fill(0);
  if (!str) return result;

  for (let d = 0; d < dims; d++) {
    let hash = 2166136261 ^ (d * 0x9e3779b9);
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    result[d] = ((hash >>> 0) % 1000) / 1000;
  }
  return result;
}

/**
 * Parse screen dimensions string "WxH" to normalized values.
 */
function parseScreenDims(dims: string | undefined): [number, number] {
  if (!dims) return [0, 0];
  const parts = dims.split("x");
  if (parts.length !== 2) return [0, 0];
  const width = parseInt(parts[0], 10);
  const height = parseInt(parts[1], 10);
  if (isNaN(width) || isNaN(height)) return [0, 0];
  return [normalize(width, 320, 7680), normalize(height, 240, 4320)];
}

/**
 * Encode IPv4 to 8 normalized dimensions preserving network structure.
 * Two IPs in the same /24 subnet will have 7 of 8 dimensions identical,
 * making them very close in vector space (unlike hashing which destroys proximity).
 */
function encodeIPv4(ip: string | undefined): number[] {
  if (!ip) return new Array(8).fill(0);

  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return new Array(8).fill(0);
  }

  // Direct octet encoding (preserves subnet similarity)
  const octets = parts.map((p) => p / 255);

  // Network class encoding (coarse grouping)
  const isPrivate =
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168);

  // Hierarchical network encodings
  const classA = parts[0] / 255; // /8 network
  const classB = (parts[0] * 256 + parts[1]) / 65535; // /16 network
  const subnet24 = (parts[0] * 65536 + parts[1] * 256 + parts[2]) / 16777215; // /24 subnet

  return [
    ...octets, // 4 dims: individual octets
    classA, // 1 dim: /8 network
    classB, // 1 dim: /16 network
    subnet24, // 1 dim: /24 subnet
    isPrivate ? 1 : 0, // 1 dim: private network flag
  ];
}

/**
 * Encode ASN to 3 normalized dimensions.
 * Uses log-normalization to compress the wide ASN range (1 - 400000+).
 */
function encodeAsn(asn: number | undefined): number[] {
  if (asn === undefined || asn === null || isNaN(asn)) {
    return [0, 0, 0];
  }

  const maxAsn = 400000;

  // Log-normalized magnitude (compresses range nicely)
  const logNorm = Math.log1p(asn) / Math.log1p(maxAsn);

  // Rough RIR grouping (geographic signal)
  // ARIN (North America): 1-2000, 6000-8000
  // RIPE (Europe): 3000-5000, 8000-10000
  // APNIC (Asia-Pacific): 45000+
  let rirScore = 0.5;
  if (asn < 2000 || (asn >= 6000 && asn < 8000)) {
    rirScore = 0.2; // ARIN
  } else if ((asn >= 3000 && asn < 5000) || (asn >= 8000 && asn < 10000)) {
    rirScore = 0.4; // RIPE
  } else if (asn >= 45000) {
    rirScore = 0.8; // APNIC
  }

  // Lower bits for discrimination within similar ranges
  const lowerBits = (asn % 1000) / 1000;

  return [logNorm, rirScore, lowerBits];
}

/**
 * Check if this is Brave browser in private mode.
 * In this mode, canvas/audio/webgl fingerprints are randomized and useless.
 */
function isBravePrivate(fp: Fingerprint): boolean {
  return fp.privacy_browser === "brave" && fp.is_private_browsing === true;
}

// ============================================================================
// SECTION BUILDERS
// ============================================================================

/** Build structural hashes section (48 dims) */
function buildStructuralSection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.html_element_hash, 8),
    ...hashToBipolar(fp.maths_hash, 8),
    ...hashToBipolar(fp.window_features_hash, 8),
    ...hashToBipolar(fp.css_hash, 8),
    ...hashToBipolar(fp.svg_hash, 8),
    ...hashToBipolar(fp.intl_hash, 8),
  ];
}

/** Build rendering section (48 dims) */
function buildRenderingSection(fp: Fingerprint): number[] {
  // For Brave/private mode, canvas/audio/webgl are randomized - zero them out
  // to prevent false negatives. Rely on structural and network signals instead.
  if (isBravePrivate(fp)) {
    return [
      ...new Array(12).fill(0), // canvas - randomized
      ...new Array(12).fill(0), // webgl - randomized
      ...new Array(8).fill(0), // audio - randomized
      ...hashToBipolar(fp.client_rects_hash, 8), // might be stable
      ...stringToVector(fp.gpu_renderer, 8), // stable
    ];
  }

  return [
    ...hashToBipolar(fp.canvas_hash, 12),
    ...hashToBipolar(fp.webgl_hash, 12),
    ...hashToBipolar(fp.audio_hash, 8),
    ...hashToBipolar(fp.client_rects_hash, 8),
    ...stringToVector(fp.gpu_renderer, 8),
  ];
}

/** Build hardware section (32 dims) */
function buildHardwareSection(fp: Fingerprint): number[] {
  const [screenW, screenH] = parseScreenDims(fp.screen_dims);
  return [
    normalize(fp.hardware_concurrency, 1, 128),
    normalize(fp.device_memory, 0.5, 64),
    normalize(fp.webgl_extensions_count, 0, 100),
    screenW,
    screenH,
    ...stringToVector(fp.user_agent, 27),
  ];
}

/** Build network section (32 dims) - EXPANDED for better network identity */
function buildNetworkSection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.ja3, 8), // TLS fingerprint - very stable
    ...hashToBipolar(fp.ja4, 8), // TLS fingerprint - very stable
    ...encodeIPv4(fp.ip_address ?? fp.stun_public_ip), // 8 dims - preserves proximity
    ...encodeAsn(fp.asn), // 3 dims - network identity
    normalize(fp.tcp_rtt_us, 0, 500000),
    normalize(fp.snd_mss, 500, 1500), // TCP tuning signal
    normalize(fp.pmtu, 500, 9001), // Path MTU signal
    fp.proxy_score ?? 0,
    fp.vpn_score ?? 0,
  ];
}

/** Build behavioral section (22 dims) */
function buildBehavioralSection(fp: Fingerprint): number[] {
  return [
    ...stringToVector(fp.timezone, 8), // 8 dims
    normalize(fp.timezone_offset, -720, 840), // 1 dim: UTC offset in minutes
    boolToNum(fp.is_private_browsing), // 1 dim
    boolToNum(fp.privacy_browser === "brave"), // 1 dim
    boolToNum(fp.privacy_browser === "firefox_rfp"), // 1 dim
    boolToNum(fp.is_headless), // 1 dim
    normalize(fp.lie_count, 0, 20), // 1 dim
    ...hashToBipolar(fp.features_hash, 8), // 8 dims
  ]; // Total: 22 dims
}

/** Build identity section (16 dims) */
function buildIdentitySection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.stable_hash, 8),
    ...hashToBipolar(fp.fuzzy_hash, 8),
  ];
}

// ============================================================================
// MAIN EMBEDDING FUNCTION
// ============================================================================

/**
 * Compute a 256-dimensional fingerprint embedding vector.
 *
 * Structure (v3):
 * [0-47]   Structural hashes (48 dims) - stable even in privacy browsers
 * [48-95]  Rendering (48 dims) - zeroed for Brave/private
 * [96-127] Hardware (32 dims)
 * [128-159] Network (32 dims) - IP octets, ASN, JA3/JA4, TCP tuning
 * [160-181] Behavioral (22 dims)
 * [182-197] Identity (16 dims)
 * [198-255] Reserved (58 dims)
 *
 * @param fingerprint - Normalized fingerprint data
 * @returns Embedding result with vector and metadata
 */
export function computeEmbedding(fingerprint: Fingerprint): EmbeddingResult {
  const vector = [
    ...buildStructuralSection(fingerprint),
    ...buildRenderingSection(fingerprint),
    ...buildHardwareSection(fingerprint),
    ...buildNetworkSection(fingerprint),
    ...buildBehavioralSection(fingerprint),
    ...buildIdentitySection(fingerprint),
  ];

  // Pad remaining with zeros for future expansion
  const remainingDims = EMBEDDING_DIMENSIONS - vector.length;
  const padding = new Array(remainingDims).fill(0);

  return {
    vector: [...vector, ...padding],
    dimensions: EMBEDDING_DIMENSIONS,
    version: EMBEDDING_VERSION,
  };
}

/**
 * Check if two embeddings are compatible for comparison.
 * Embeddings with different versions may not be directly comparable.
 */
export function areEmbeddingsCompatible(
  a: EmbeddingResult,
  b: EmbeddingResult,
): boolean {
  return a.version === b.version && a.dimensions === b.dimensions;
}
