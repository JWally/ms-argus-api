/**
 * @fileoverview Application-wide constants and configuration values.
 *
 * Contains TTLs, limits, thresholds, and feature flag accessors used
 * throughout the Argus fingerprinting system. Constants are organized
 * by domain (caching, matching, profiles, SimHash).
 *
 * @module helpers/constants
 */

/** Cache duration for AWS Secrets: 15 minutes (900,000ms) */
export const KEY_CACHE_DURATION: number = 1000 * 60 * 15;

/** Cache duration for API Keys: 5 minutes (300,000ms) */
export const API_KEYS_CACHE_TTL: number = 1000 * 60 * 5;

/** FNV-1a 32-bit offset basis (standard value) */
export const FNV1A_OFFSET_BASIS = 2166136261;

/** FNV-1a 32-bit prime (standard value) */
export const FNV1A_PRIME = 16777619;

/** Session cache TTL in DynamoDB: 15 minutes (900 seconds) */
export const SESSION_TTL_SECONDS = 900;

/** Session payload TTL: 30 minutes (1800 seconds) - full payload for gRPC stub */
export const SESSION_PAYLOAD_TTL_SECONDS = 1800;

/** Tier2 matching timeout: 500ms - fail open if query takes too long */
export const TIER2_TIMEOUT_MS = 500;

/** Max devices per Tier2 bucket query - prevents runaway queries */
export const TIER2_BUCKET_LIMIT = 1000;

/** Cardinality threshold for high-traffic buckets (e.g., carrier NAT) */
export const TIER2_HIGH_CARDINALITY_THRESHOLD = 500;

/** Confidence penalty factor for high-cardinality bucket matches */
export const TIER2_CARDINALITY_PENALTY = 0.3;

/** Sort key for bucket stats items in Tier2Buckets table */
export const TIER2_STATS_SK = "_stats";

/** Confidence penalty for privacy browser detection (Brave, Firefox RFP, Tor, etc.) */
export const PRIVACY_BROWSER_PENALTY = 0.15;

/** Confidence penalty for private/incognito browsing mode */
export const PRIVATE_BROWSING_PENALTY = 0.1;

/** Profile TTL in DynamoDB: 60 days */
export const PROFILE_TTL_DAYS = 60;

/** Tier 2 bucket TTL in DynamoDB: 7 days */
export const TIER2_BUCKET_TTL_DAYS = 7;

/** Session anchor validity window: 10 minutes (600 seconds)
 * Application-enforced TTL for short-window device matching */
export const SESSION_ANCHOR_VALIDITY_SECONDS = 600;

/** Session anchor DynamoDB cleanup TTL: 1 hour (3600 seconds)
 * DynamoDB TTL is eventually consistent, so we set a longer TTL for cleanup
 * while enforcing the actual validity window in application code */
export const SESSION_ANCHOR_CLEANUP_TTL_SECONDS = 3600;

/** IP+UA-only anchor validity window: 3 minutes (180 seconds)
 * Shorter window than session anchor since it's less specific (no screen_dims).
 * Catches cases where screen changes (dock/undock) but IP+UA stays same. */
export const IP_UA_ANCHOR_VALIDITY_SECONDS = 180;

/** Mutation gate TTL: 1 hour (3600 seconds) - prevents rapid repeated writes */
export const MUTATION_GATE_TTL_SECONDS = 3600;

/** Max entries in request deduplication LRU cache */
export const DEDUPE_CACHE_MAX_ENTRIES = 30_000;

/** Deduplication cache TTL: 30 seconds */
export const DEDUPE_CACHE_TTL_MS = 30_000;

export const AWS_SECRETS_REQUIRED_KEYS: string[] = [
  "ENCRYPTION_KEY",
  "HMAC_KEY",
];

export const ERROR_STRINGS = {
  SECRETS_MANAGER_FAILED: "Failed to retrieve secrets from Secrets Manager",
  KEY_ARN_NOT_SET: "Environment variables SECRET_KEY_ARN must be set",
  CANNOT_PARSE_JSON: "Cannot Parse JSON Data",
  CANNOT_DECRYPT: "Cannot Decrypt Payload",
  CANNOT_VERIFY_SIGNATURE: "Cannot Verify Signature",
};

/**
 * SimHash LSH Configuration
 * Splits 64-bit fuzzy_hash into bands for locality-sensitive lookup
 */
export const SIMHASH_CONFIG = {
  /** Number of band partitions for LSH */
  NUM_BANDS: 4,
  /** Bits per band (4 bands x 16 bits = 64 bits total) */
  BITS_PER_BAND: 16,
  /** Max Hamming distance bits to accept a match */
  HAMMING_THRESHOLD: 4,
  /** Require this many bands to match for candidacy */
  MIN_BANDS_MATCH: 2,
  /** Band entry TTL in days */
  BAND_TTL_DAYS: 90,
  /** Per-band query LIMIT to prevent hot-band explosion */
  PER_BAND_LIMIT: 100,
  /** Max candidates to score after band aggregation */
  MAX_CANDIDATES: 100,
  /** Last-seen recency window in days for loose Hamming threshold (>1 bit) */
  RECENCY_WINDOW_DAYS: 30,
} as const;

/**
 * SimHash Feature Flags - runtime configuration via environment variables
 * Provides kill switch, shadow mode, and gradual rollout controls
 */
export const getSimHashFlags = () => ({
  /** Master enable/disable (kill switch) */
  ENABLED: process.env.SIMHASH_ENABLED === "true",
  /** Shadow mode - compute and log but don't use result for matching */
  SHADOW_MODE: process.env.SIMHASH_SHADOW === "true",
  /** Percentage rollout (0-100) for gradual enablement */
  ROLLOUT_PERCENT: parseInt(process.env.SIMHASH_ROLLOUT || "100", 10),
  /** Automatic bypass if tier query exceeds this latency (ms) */
  LATENCY_BYPASS_MS: parseInt(process.env.SIMHASH_LATENCY_BYPASS || "150", 10),
  /** Override Hamming threshold from env (for tuning without redeploy) */
  HAMMING_THRESHOLD: parseInt(
    process.env.SIMHASH_HAMMING_THRESHOLD ||
      String(SIMHASH_CONFIG.HAMMING_THRESHOLD),
    10,
  ),
  /** Override max candidates from env */
  MAX_CANDIDATES: parseInt(
    process.env.SIMHASH_MAX_CANDIDATES || String(SIMHASH_CONFIG.MAX_CANDIDATES),
    10,
  ),
});
