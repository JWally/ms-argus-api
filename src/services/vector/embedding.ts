/**
 * @fileoverview Fingerprint embedding service.
 *
 * Converts normalized fingerprint data into a 512-dimensional vector
 * suitable for similarity search in Qdrant.
 *
 * Embedding structure (v12 — 512d, v9_512 layout with network ablation):
 * [0-190]   Structural (191d): cssMedia(68), css(34), screen(33),
 *           htmlElement(24), maths(8), window(8), svg(8), intl(8)
 * [191-266] Rendering  ( 76d): canvas(20), webgl(16), audio(8),
 *           clientRects(16), gpu(16)
 * [267-310] Hardware   ( 44d): hw_conc(1), dev_mem(1), webgl_ext(1),
 *           screen_dims(16), platform(8), user_agent(16), hw_conc2(1)
 * [311-315] Network    (  5d): all zeroed (ablation: +0.8pp R@1)
 * [316-379] Behavioral ( 64d): timezone(24), tz_offset(1), privacy(4),
 *           lie_count(1), features_hash(34)
 * [380-511] Identity   (132d): fuzzy_hash(132)
 *
 * v12: v9_512 layout chosen over v11 after testing 1,612 payloads / 159 devices.
 *   Restores Hardware & Identity sections that v11 dropped (trained on only 110/3).
 *   Network dims zeroed per ablation results. MAP 0.9434, R@1 ~95.2%.
 * v11: 512d, 3 sections (Structural 322, Rendering 164, Behavioral 26)
 * v10: 256d, 3 sections (Structural 128, Rendering 104, Behavioral 24)
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
export const EMBEDDING_VERSION = 12;

/**
 * Weighted embedding version for per-OS NSGA-II profiles.
 * Uses v12 base embedding with element-wise weight multiplication.
 */
export const WEIGHTED_EMBEDDING_VERSION = 13;

/**
 * Expected number of dimensions for the current embedding version.
 */
export const EMBEDDING_DIMENSIONS = 512;

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
 * Check if this is Brave browser in private mode.
 * In this mode, canvas/audio/webgl fingerprints are all randomized.
 */
function isBravePrivate(fp: Fingerprint): boolean {
  return fp.privacy_browser === "brave" && fp.is_private_browsing === true;
}

/**
 * Check if this is Firefox with Resist Fingerprinting (RFP) in private mode.
 * RFP randomizes canvas and webgl per-session, but audio stays stable.
 */
function isFirefoxRFPPrivate(fp: Fingerprint): boolean {
  return (
    fp.privacy_browser === "firefox_rfp" && fp.is_private_browsing === true
  );
}

/**
 * Detect browser variant from UA string.
 * Mirrors vector-match.ts detectBrowserVariant for embedding use.
 */
function detectBrowserVariant(ua: string | undefined): string {
  if (!ua) return "unknown";
  if (/FxiOS/i.test(ua)) return "fxios";
  if (/CriOS/i.test(ua)) return "crios";
  if (/EdgiOS/i.test(ua)) return "edgios";
  if (/Firefox/i.test(ua)) return "firefox";
  if (/Edg\//i.test(ua)) return "edge";
  if (/Chrome/i.test(ua)) return "chrome";
  if (/Safari/i.test(ua)) return "safari";
  return "unknown";
}

/**
 * Check if this is an iOS device (any browser).
 * iOS randomizes canvas in all modes and audio varies every visit.
 */
function isIOS(fp: Fingerprint): boolean {
  return /iPhone|iPad|iPod/i.test(fp.platform ?? "");
}

/**
 * Check if this is Safari in private mode on macOS.
 * Safari private randomizes canvas per session; audio has subtle FP noise
 * that shifts the exact hash but simhash absorbs it.
 */
function isSafariPrivate(fp: Fingerprint): boolean {
  return (
    detectBrowserVariant(fp.user_agent) === "safari" &&
    fp.is_private_browsing === true &&
    !isIOS(fp) // iOS handled separately (always randomized)
  );
}

// ============================================================================
// SECTION BUILDERS
// ============================================================================

/** Build structural hashes section (191 dims) */
function buildStructuralSection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.css_media_simhash ?? fp.css_media_hash, 68),
    ...hashToBipolar(fp.css_simhash ?? fp.css_hash, 34),
    ...hashToBipolar(fp.screen_simhash ?? fp.screen_hash, 33),
    ...hashToBipolar(fp.html_element_simhash ?? fp.html_element_hash, 24),
    ...hashToBipolar(fp.maths_simhash ?? fp.maths_hash, 8),
    ...hashToBipolar(fp.window_features_simhash ?? fp.window_features_hash, 8),
    ...hashToBipolar(fp.svg_simhash ?? fp.svg_hash, 8),
    ...hashToBipolar(fp.intl_simhash ?? fp.intl_hash, 8),
  ]; // 68+34+33+24+8+8+8+8 = 191
}

/**
 * Determine which rendering signals are volatile for this fingerprint.
 * Returns flags for which signals should be zeroed in the embedding.
 *
 * Rationale per browser/platform:
 * - Brave private:        canvas + webgl + audio all randomized
 * - Firefox RFP private:  canvas + webgl randomized, audio stable
 * - iOS (all modes):      canvas always randomized, audio varies every visit, webgl stable
 * - macOS Safari private: canvas randomized per session, webgl differs between modes
 */
function detectVolatileRendering(fp: Fingerprint): {
  zeroCanvas: boolean;
  zeroWebgl: boolean;
  zeroAudio: boolean;
} {
  if (isBravePrivate(fp))
    return { zeroCanvas: true, zeroWebgl: true, zeroAudio: true };
  if (isFirefoxRFPPrivate(fp))
    return { zeroCanvas: true, zeroWebgl: true, zeroAudio: false };
  if (isIOS(fp)) return { zeroCanvas: true, zeroWebgl: false, zeroAudio: true };
  if (isSafariPrivate(fp))
    return { zeroCanvas: true, zeroWebgl: true, zeroAudio: false };
  return { zeroCanvas: false, zeroWebgl: false, zeroAudio: false };
}

/** Build rendering section (76 dims) — volatile signals zeroed per browser/platform */
function buildRenderingSection(fp: Fingerprint): number[] {
  const { zeroCanvas, zeroWebgl, zeroAudio } = detectVolatileRendering(fp);

  return [
    ...(zeroCanvas
      ? new Array(20).fill(0)
      : hashToBipolar(fp.canvas_simhash ?? fp.canvas_hash, 20)),
    ...(zeroWebgl
      ? new Array(16).fill(0)
      : hashToBipolar(fp.webgl_simhash ?? fp.webgl_hash, 16)),
    ...(zeroAudio
      ? new Array(8).fill(0)
      : hashToBipolar(fp.audio_simhash ?? fp.audio_hash, 8)),
    ...hashToBipolar(fp.client_rects_simhash ?? fp.client_rects_hash, 16),
    ...stringToVector(fp.gpu_renderer, 16),
  ]; // 20+16+8+16+16 = 76
}

/** Build hardware section (44 dims) */
function buildHardwareSection(fp: Fingerprint): number[] {
  return [
    normalize(fp.hardware_concurrency, 1, 128),
    normalize(fp.device_memory, 0.5, 64),
    normalize(fp.webgl_extensions_count, 0, 100),
    ...stringToVector(fp.screen_dims, 16),
    ...stringToVector(fp.platform, 8),
    ...stringToVector(fp.user_agent, 16),
    normalize(fp.hardware_concurrency, 1, 16),
  ]; // 1+1+1+16+8+16+1 = 44
}

/** Build network section (5 dims) — all zeroed per ablation (+0.8pp R@1) */
function buildNetworkSection(_fp: Fingerprint): number[] {
  return new Array(5).fill(0);
}

/** Build behavioral section (64 dims) */
function buildBehavioralSection(fp: Fingerprint): number[] {
  return [
    ...stringToVector(fp.timezone, 24),
    normalize(fp.timezone_offset, -720, 840), // 1 dim
    boolToNum(fp.is_private_browsing), // 1 dim
    boolToNum(fp.privacy_browser === "brave"), // 1 dim
    boolToNum(fp.privacy_browser === "firefox_rfp"), // 1 dim
    boolToNum(fp.is_headless), // 1 dim
    normalize(fp.lie_count, 0, 20), // 1 dim
    ...hashToBipolar(fp.features_simhash ?? fp.features_hash, 34),
  ]; // 24+1+1+1+1+1+1+34 = 64
}

/** Build identity section (132 dims) */
function buildIdentitySection(fp: Fingerprint): number[] {
  return hashToBipolar(fp.fuzzy_hash, 132);
}

// ============================================================================
// MAIN EMBEDDING FUNCTION
// ============================================================================

/**
 * Compute a 512-dimensional fingerprint embedding vector.
 *
 * Structure (v12 — v9_512 layout):
 * [0-190]   Structural (191d) - cssMedia(68), css(34), screen(33),
 *           htmlElement(24), maths(8), window(8), svg(8), intl(8)
 * [191-266] Rendering  ( 76d) - canvas(20), webgl(16), audio(8),
 *           clientRects(16), gpu(16) — canvas/webgl zeroed for privacy browsers
 * [267-310] Hardware   ( 44d) - hw_conc, dev_mem, webgl_ext, screen_dims,
 *           platform, user_agent, hw_conc2
 * [311-315] Network    (  5d) - all zeroed (ablation)
 * [316-379] Behavioral ( 64d) - timezone(24), flags(7), features_hash(34)
 * [380-511] Identity   (132d) - fuzzy_hash(132)
 *
 * @param fingerprint - Normalized fingerprint data
 * @returns Embedding result with vector and metadata
 */
export function computeEmbedding(fingerprint: Fingerprint): EmbeddingResult {
  const vector = [
    ...buildStructuralSection(fingerprint), // 191
    ...buildRenderingSection(fingerprint), //  76
    ...buildHardwareSection(fingerprint), //  44
    ...buildNetworkSection(fingerprint), //   5
    ...buildBehavioralSection(fingerprint), //  64
    ...buildIdentitySection(fingerprint), // 132
  ];

  // Verify dimension count matches expected
  if (vector.length !== EMBEDDING_DIMENSIONS) {
    // Pad or truncate to maintain compatibility
    const adjusted =
      vector.length < EMBEDDING_DIMENSIONS
        ? [
            ...vector,
            ...new Array(EMBEDDING_DIMENSIONS - vector.length).fill(0),
          ]
        : vector.slice(0, EMBEDDING_DIMENSIONS);
    return {
      vector: adjusted,
      dimensions: EMBEDDING_DIMENSIONS,
      version: EMBEDDING_VERSION,
    };
  }

  return {
    vector,
    dimensions: EMBEDDING_DIMENSIONS,
    version: EMBEDDING_VERSION,
  };
}

/**
 * Compute a weighted 512-dimensional fingerprint embedding.
 *
 * Applies per-dimension NSGA-II weights to the base v12 embedding via
 * element-wise multiplication. Used by the per-OS multi-collection system (v13).
 *
 * When weights are all 1.0, the result is identical to computeEmbedding().
 *
 * @param fingerprint - Normalized fingerprint data
 * @param weights - 512-dimensional weight array from getWeightProfile()
 * @returns Embedding result with weighted vector and v13 version
 */
export function computeWeightedEmbedding(
  fingerprint: Fingerprint,
  weights: number[],
): EmbeddingResult {
  const base = computeEmbedding(fingerprint);
  const weighted = new Array(EMBEDDING_DIMENSIONS);
  for (let i = 0; i < EMBEDDING_DIMENSIONS; i++) {
    weighted[i] = base.vector[i] * weights[i];
  }
  return {
    vector: weighted,
    dimensions: EMBEDDING_DIMENSIONS,
    version: WEIGHTED_EMBEDDING_VERSION,
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

/**
 * Quality assessment result for a fingerprint.
 */
export interface EmbeddingQualityResult {
  /** Whether the fingerprint meets minimum quality threshold for embedding */
  acceptable: boolean;
  /** Quality score from 0-1 (percentage of expected signals present) */
  score: number;
  /** Count of structural hashes present (maths, css, svg, etc.) */
  structuralCount: number;
  /** Count of rendering hashes present (canvas, webgl, audio) */
  renderingCount: number;
  /** Count of hardware signals present */
  hardwareCount: number;
  /** Reason for rejection if not acceptable */
  reason?: string;
}

/**
 * Minimum thresholds for acceptable embedding quality.
 *
 * Fingerprints below these thresholds will produce sparse embeddings
 * that could pollute the vector index with false similarity matches.
 */
const QUALITY_THRESHOLDS = {
  /** Minimum structural hashes required (out of 8: cssMedia, css, screen, html, maths, window, svg, intl) */
  minStructuralHashes: 2,
  /** Minimum rendering hashes required (out of 3: canvas, webgl, audio) */
  minRenderingHashes: 1,
  /** Minimum hardware signals required (out of 4: concurrency, memory, screen, user_agent) */
  minHardwareSignals: 2,
  /** Overall minimum score (0-1) */
  minOverallScore: 0.3,
};

/**
 * Assess fingerprint quality for embedding.
 *
 * Checks that the fingerprint has sufficient data to produce a meaningful
 * embedding. Sparse fingerprints (e.g., from minimal test payloads) can
 * pollute the vector index with false similarity matches.
 *
 * @param fingerprint - Fingerprint to assess
 * @returns Quality assessment with score and acceptability
 */
// eslint-disable-next-line max-lines-per-function
export function assessEmbeddingQuality(
  fingerprint: Fingerprint,
): EmbeddingQualityResult {
  // Count structural hashes (most important for embedding quality)
  const structuralHashes = [
    fingerprint.maths_hash,
    fingerprint.window_features_hash,
    fingerprint.html_element_hash,
    fingerprint.css_hash,
    fingerprint.svg_hash,
    fingerprint.intl_hash,
    fingerprint.screen_hash,
    fingerprint.css_media_hash,
  ];
  const structuralCount = structuralHashes.filter(Boolean).length;

  // Count rendering hashes
  const renderingHashes = [
    fingerprint.canvas_hash,
    fingerprint.webgl_hash,
    fingerprint.audio_hash,
  ];
  const renderingCount = renderingHashes.filter(Boolean).length;

  // Count hardware signals
  const hardwareSignals = [
    fingerprint.hardware_concurrency,
    fingerprint.device_memory,
    fingerprint.screen_dims,
    fingerprint.user_agent,
    fingerprint.platform,
  ];
  const hardwareCount = hardwareSignals.filter(
    (v) => v !== undefined && v !== null,
  ).length;

  // Check identity hashes (required)
  const hasIdentity = !!fingerprint.stable_hash && !!fingerprint.fuzzy_hash;

  // Calculate overall score
  const maxSignals = 8 + 3 + 5 + 2; // structural + rendering + hardware + identity
  const presentSignals =
    structuralCount +
    renderingCount +
    hardwareCount +
    (fingerprint.stable_hash ? 1 : 0) +
    (fingerprint.fuzzy_hash ? 1 : 0);
  const score = presentSignals / maxSignals;

  // Determine acceptability
  let acceptable = true;
  let reason: string | undefined;

  if (!hasIdentity) {
    acceptable = false;
    reason = "Missing identity hashes (stable_hash or fuzzy_hash)";
  } else if (structuralCount < QUALITY_THRESHOLDS.minStructuralHashes) {
    acceptable = false;
    reason = `Insufficient structural hashes: ${structuralCount}/${QUALITY_THRESHOLDS.minStructuralHashes} required`;
  } else if (
    renderingCount < QUALITY_THRESHOLDS.minRenderingHashes &&
    structuralCount < 4
  ) {
    // Allow low rendering if structural is strong (e.g., Brave browser)
    acceptable = false;
    reason = `Insufficient rendering hashes: ${renderingCount}/${QUALITY_THRESHOLDS.minRenderingHashes} required (or need 4+ structural)`;
  } else if (hardwareCount < QUALITY_THRESHOLDS.minHardwareSignals) {
    acceptable = false;
    reason = `Insufficient hardware signals: ${hardwareCount}/${QUALITY_THRESHOLDS.minHardwareSignals} required`;
  } else if (score < QUALITY_THRESHOLDS.minOverallScore) {
    acceptable = false;
    reason = `Overall quality score too low: ${(score * 100).toFixed(0)}% < ${QUALITY_THRESHOLDS.minOverallScore * 100}%`;
  }

  return {
    acceptable,
    score,
    structuralCount,
    renderingCount,
    hardwareCount,
    reason,
  };
}
