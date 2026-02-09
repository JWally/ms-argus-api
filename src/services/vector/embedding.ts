/**
 * @fileoverview Fingerprint embedding service.
 *
 * Converts normalized fingerprint data into a 256-dimensional vector
 * suitable for similarity search in Qdrant.
 *
 * Embedding structure (v7 - data-driven iOS rebalance):
 * - Structural hashes (80 dims): cssMedia(24), css(16), screen(12),
 *   htmlElement(12), maths(4), windowFeatures(4), svg(4), intl(4).
 *   Weights based on XGBoost feature importance analysis (59 payloads, F1=0.96).
 * - Rendering (36 dims): canvas(8), webgl(8), audio(4), clientRects(8), gpu(8)
 *   Reduced — only 3.3% importance for iOS differentiation.
 * - Hardware (24 dims): concurrency, memory, webgl ext, screen (8 dims via
 *   stringToVector), platform (4 dims), UA (8 dims)
 * - Network (46 dims): JA3/JA4, IP, ASN, H2 (14 dims), TCP tuning
 * - Behavioral (22 dims): timezone, privacy flags, headless, lie count, features
 * - Identity (48 dims): fuzzy hash (48 dims)
 *
 * Key improvements in v7 (data-driven rebalance):
 * - cssMedia boosted 8→24 dims (#1 iOS discriminator at 28.4% importance)
 * - css boosted 8→16 dims (#4 discriminator at 11.3%)
 * - screen/htmlElement boosted 8→12 each
 * - maths/svg/intl/windowFeatures shrunk 8→4 (0.0-0.2% importance)
 * - Rendering shrunk 48→36 (3.3% total importance for iOS)
 * - Identity shrunk 52→48
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
 * v7: Data-driven rebalance - cssMedia/css/screen boosted, rendering/identity shrunk
 * v6: iOS differentiation - screen/cssMedia structural, platform encoding, fuzzy shrink
 * v5: SimHash preference, H2 decomposition, drop stable_hash, expand fuzzy
 * v4: Expanded fuzzy_hash from 8 to 64 dims for 256-bit SimHash support
 * v3: Improved IP/ASN encoding, Brave/private handling, JA3/JA4 as bipolar
 */
export const EMBEDDING_VERSION = 7;

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
 * Convert a string to a hex representation via FNV-1a hashing.
 * Produces a deterministic hex string suitable for hashToBipolar.
 */
function stringToHex(str: string): string {
  // Use multiple FNV-1a rounds to produce enough hex chars
  const hexChars: string[] = [];
  for (let seed = 0; hexChars.length < 16; seed++) {
    let hash = 2166136261 ^ (seed * 0x9e3779b9);
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    hexChars.push((hash >>> 0).toString(16).padStart(8, "0"));
  }
  return hexChars.join("");
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
// eslint-disable-next-line complexity
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

/** Build structural hashes section (80 dims) - weighted by feature importance */
function buildStructuralSection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.css_media_simhash ?? fp.css_media_hash, 24), // #1 discriminator (28.4%)
    ...hashToBipolar(fp.css_simhash ?? fp.css_hash, 16), // #4 discriminator (11.3%)
    ...hashToBipolar(fp.screen_simhash ?? fp.screen_hash, 12), // #2 discriminator (14.5%)
    ...hashToBipolar(fp.html_element_simhash ?? fp.html_element_hash, 12), // #6 discriminator (5.6%)
    ...hashToBipolar(fp.maths_simhash ?? fp.maths_hash, 4), // 0.0% importance
    ...hashToBipolar(fp.window_features_simhash ?? fp.window_features_hash, 4), // 0.2%
    ...hashToBipolar(fp.svg_simhash ?? fp.svg_hash, 4), // 0.0%
    ...hashToBipolar(fp.intl_simhash ?? fp.intl_hash, 4), // 0.0%
  ];
}

/** Build rendering section (36 dims) - reduced, only 3.3% iOS importance */
function buildRenderingSection(fp: Fingerprint): number[] {
  // For Brave/private mode, canvas/audio/webgl are randomized - zero them out
  // to prevent false negatives. Rely on structural and network signals instead.
  if (isBravePrivate(fp)) {
    return [
      ...new Array(8).fill(0), // canvas - randomized
      ...new Array(8).fill(0), // webgl - randomized
      ...new Array(4).fill(0), // audio - randomized
      ...hashToBipolar(fp.client_rects_hash, 8), // might be stable
      ...stringToVector(fp.gpu_renderer, 8), // stable
    ];
  }

  return [
    ...hashToBipolar(fp.canvas_simhash ?? fp.canvas_hash, 8),
    ...hashToBipolar(fp.webgl_simhash ?? fp.webgl_hash, 8),
    ...hashToBipolar(fp.audio_simhash ?? fp.audio_hash, 4),
    ...hashToBipolar(fp.client_rects_hash, 8),
    ...stringToVector(fp.gpu_renderer, 8),
  ];
}

/** Build hardware section (24 dims) */
function buildHardwareSection(fp: Fingerprint): number[] {
  return [
    normalize(fp.hardware_concurrency, 1, 128), // 1 dim
    normalize(fp.device_memory, 0.5, 64), // 1 dim
    normalize(fp.webgl_extensions_count, 0, 100), // 1 dim
    ...stringToVector(fp.screen_dims, 8), // 8 dims - maximally different per resolution
    ...stringToVector(fp.platform, 4), // 4 dims - iPhone vs iPad vs desktop
    ...stringToVector(fp.user_agent, 8), // 8 dims
    normalize(fp.hardware_concurrency, 1, 16), // 1 dim - tighter mobile range
  ];
}

/**
 * Encode H2 fingerprint to 14 dimensions.
 * - 6 dims: HTTP/2 settings (HEADER_TABLE_SIZE through MAX_HEADER_LIST_SIZE)
 * - 1 dim: window_update (most discriminating single H2 value)
 * - 3 dims: pseudo_header_order as bipolar hash
 * - 4 dims: header_order as bipolar hash
 */
function encodeH2(fp: Fingerprint): number[] {
  // Parse settings from settings_order array: ["1:65536", "2:0", "4:131072", ...]
  const settings = new Array(6).fill(0);
  if (fp.h2_settings_order) {
    for (const entry of fp.h2_settings_order) {
      const [idStr, valStr] = entry.split(":");
      const id = parseInt(idStr, 10);
      const val = parseInt(valStr, 10);
      if (id >= 1 && id <= 6 && !isNaN(val)) {
        // Normalize each setting to 0-1 based on typical ranges
        const maxValues: Record<number, number> = {
          1: 65536, // HEADER_TABLE_SIZE
          2: 1, // ENABLE_PUSH (boolean 0/1)
          3: 1000, // MAX_CONCURRENT_STREAMS
          4: 16777215, // INITIAL_WINDOW_SIZE
          5: 16777215, // MAX_FRAME_SIZE
          6: 16777215, // MAX_HEADER_LIST_SIZE
        };
        settings[id - 1] = normalize(val, 0, maxValues[id]);
      }
    }
  }

  // window_update normalized
  const windowUpdate = normalize(fp.h2_window_update, 0, 16777215);

  // pseudo_header_order as bipolar hash (3 dims)
  const pseudoHeader = hashToBipolar(
    fp.h2_pseudo_header_order
      ? stringToHex(fp.h2_pseudo_header_order)
      : undefined,
    3,
  );

  // header_order as bipolar hash (4 dims)
  const headerOrder = hashToBipolar(
    fp.h2_header_order ? stringToHex(fp.h2_header_order.join(",")) : undefined,
    4,
  );

  return [...settings, windowUpdate, ...pseudoHeader, ...headerOrder];
}

/** Build network section (46 dims) - expanded with H2 fingerprint */
function buildNetworkSection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.ja3, 8), // 8 dims - TLS fingerprint
    ...hashToBipolar(fp.ja4, 8), // 8 dims - TLS fingerprint
    ...encodeIPv4(fp.ip_address ?? fp.stun_public_ip), // 8 dims - preserves proximity
    ...encodeAsn(fp.asn), // 3 dims - network identity
    ...encodeH2(fp), // 14 dims - H2 fingerprint
    normalize(fp.tcp_rtt_us, 0, 500000), // 1 dim
    normalize(fp.snd_mss, 500, 1500), // 1 dim - TCP tuning
    normalize(fp.pmtu, 500, 9001), // 1 dim - Path MTU
    fp.proxy_score ?? 0, // 1 dim
    fp.vpn_score ?? 0, // 1 dim
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

/** Build identity section (48 dims) - fuzzy hash only */
function buildIdentitySection(fp: Fingerprint): number[] {
  return [
    ...hashToBipolar(fp.fuzzy_hash, 48), // 48 dims
  ];
}

// ============================================================================
// MAIN EMBEDDING FUNCTION
// ============================================================================

/**
 * Compute a 256-dimensional fingerprint embedding vector.
 *
 * Structure (v7):
 * [0-79]   Structural hashes (80 dims) - cssMedia(24), css(16), screen(12), htmlElement(12), rest(16)
 * [80-115] Rendering (36 dims) - zeroed for Brave/private
 * [116-139] Hardware (24 dims) - concurrency, memory, screen (8d), platform (4d), UA
 * [140-185] Network (46 dims) - JA3/JA4, IP, ASN, H2 (14), TCP tuning
 * [186-207] Behavioral (22 dims)
 * [208-255] Identity (48 dims) - fuzzy hash
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

  // Verify dimension count matches expected (no padding needed in v7)
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
