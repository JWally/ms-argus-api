/**
 * @fileoverview Fingerprint embedding service.
 *
 * Converts normalized fingerprint data into a 256-dimensional vector
 * suitable for similarity search in Qdrant.
 *
 * Embedding structure (based on field analysis):
 * - Structural hashes (48 dims): htmlElement, maths, fonts, windowFeatures, css, svg
 * - Rendering (48 dims): canvas, webgl, audio, gpu
 * - Hardware (32 dims): concurrency, memory, screen, webgl extensions
 * - Network (24 dims): TLS fingerprints (ja3/ja4), TCP RTT, proxy/vpn scores
 * - Behavioral (24 dims): timezone, privacy, headless, lie count
 * - Identity (16 dims): stable hash, fuzzy hash
 * - Reserved (64 dims): future expansion
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
 */
export const EMBEDDING_VERSION = 2;

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

/** Build network section (24 dims) */
function buildNetworkSection(fp: Fingerprint): number[] {
  return [
    ...stringToVector(fp.ja3, 8),
    ...stringToVector(fp.ja4, 8),
    normalize(fp.tcp_rtt_us, 0, 500000),
    fp.proxy_score ?? 0,
    fp.vpn_score ?? 0,
    stringToFloat(fp.ip_address),
    stringToFloat(fp.stun_public_ip),
    stringToFloat(fp.stun_local_ip),
  ];
}

/** Build behavioral section (24 dims) */
function buildBehavioralSection(fp: Fingerprint): number[] {
  return [
    ...stringToVector(fp.timezone, 8),
    boolToNum(fp.is_private_browsing),
    fp.privacy_browser ? 1 : 0,
    boolToNum(fp.is_headless),
    normalize(fp.lie_count, 0, 20),
    ...hashToBipolar(fp.features_hash, 8),
    ...hashToBipolar(fp.console_errors_hash, 4),
  ];
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
 * Structure:
 * [0-47]   Structural hashes (48 dims)
 * [48-95]  Rendering (48 dims)
 * [96-127] Hardware (32 dims)
 * [128-151] Network (24 dims)
 * [152-175] Behavioral (24 dims)
 * [176-191] Identity (16 dims)
 * [192-255] Reserved (64 dims)
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
