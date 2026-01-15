// src/helpers/constants.ts
import { Options } from "@middy/http-cors";

export const SECURITY_KEY_NAME = "argus-keys";

// ==================== CACHE & TTL CONSTANTS ====================

/** Cache duration for AWS Secrets: 15 minutes (900,000ms) */
export const KEY_CACHE_DURATION: number = 1000 * 60 * 15;

// ==================== FNV-1A HASH CONSTANTS ====================
// Used for fast idempotency key generation and request deduplication
// See: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function

/** FNV-1a 32-bit offset basis (standard value) */
export const FNV1A_OFFSET_BASIS = 2166136261;

/** FNV-1a 32-bit prime (standard value) */
export const FNV1A_PRIME = 16777619;

// ==================== MATCHING SERVICE CONSTANTS ====================

/** Session cache TTL in DynamoDB: 15 minutes (900 seconds) - AR-52: was Redis */
export const SESSION_TTL_SECONDS = 900;

/** Tier2 matching timeout: 500ms - fail open if query takes too long */
// AR-80: Increased from 100ms to 500ms to accommodate 6 bucket queries
export const TIER2_TIMEOUT_MS = 500;

/** Max devices per Tier2 bucket query - prevents runaway queries */
export const TIER2_BUCKET_LIMIT = 1000;

/** AR-56: Cardinality threshold for high-traffic buckets (e.g., carrier NAT) */
export const TIER2_HIGH_CARDINALITY_THRESHOLD = 500;

/** AR-56: Confidence penalty factor for high-cardinality bucket matches */
export const TIER2_CARDINALITY_PENALTY = 0.3;

/** AR-56: Sort key for bucket stats items in Tier2Buckets table */
export const TIER2_STATS_SK = "_stats";

/** AR-65: Confidence penalty for privacy browser detection (Brave, Firefox RFP, Tor, etc.) */
export const PRIVACY_BROWSER_PENALTY = 0.15;

/** AR-65: Confidence penalty for private/incognito browsing mode */
export const PRIVATE_BROWSING_PENALTY = 0.1;

// ==================== PROFILE SERVICE CONSTANTS ====================

/** Profile TTL in DynamoDB: 60 days */
export const PROFILE_TTL_DAYS = 60;

/** Tier 2 bucket TTL in DynamoDB: 7 days (AR-39: prevent accumulation) */
export const TIER2_BUCKET_TTL_DAYS = 7;

/** AR-82: Session anchor validity window: 10 minutes (600 seconds)
 * Application-enforced TTL for short-window device matching */
export const SESSION_ANCHOR_VALIDITY_SECONDS = 600;

/** AR-82: Session anchor DynamoDB cleanup TTL: 1 hour (3600 seconds)
 * DynamoDB TTL is eventually consistent, so we set a longer TTL for cleanup
 * while enforcing the actual validity window in application code */
export const SESSION_ANCHOR_CLEANUP_TTL_SECONDS = 3600;

/** Mutation gate TTL: 1 hour (3600 seconds) - prevents rapid repeated writes */
export const MUTATION_GATE_TTL_SECONDS = 3600;

// ==================== DEDUPLICATION CACHE CONSTANTS ====================

/** Max entries in request deduplication LRU cache */
export const DEDUPE_CACHE_MAX_ENTRIES = 30_000;

/** Deduplication cache TTL: 30 seconds */
export const DEDUPE_CACHE_TTL_MS = 30_000;

export const DEFAULT_HEADERS = {
  "Content-Security-Policy": "default-src 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Download-Options": "noopen",
  "X-Frame-Options": "DENY",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Referrer-Policy": "no-referrer",
  "X-XSS-Protection": "1; mode=block",
} as const;

export const ALLOWED_HEADERS = [
  "Content-Type",
  "X-Amz-Date",
  "Authorization",
  "X-Api-Key",
  "X-Amz-Security-Token",
  "X-Amz-User-Agent",
  "Accept",
  "Accept-Language",
  "Content-Language",
  "Origin",
  "X-Requested-With",
];

/**
 * Parse ALLOWED_ORIGINS from environment variable.
 * Format: comma-separated list of origins (e.g., "https://app.argus.pw,https://dashboard.argus.pw")
 * Falls back to safe defaults for dev environment.
 */
const parseAllowedOrigins = (): string[] => {
  const envOrigins = process.env.ALLOWED_ORIGINS;
  if (envOrigins) {
    return envOrigins.split(",").map((origin) => origin.trim());
  }
  // Default origins for development - these should be overridden in production
  return [
    "https://api-dev-jw.argus.pw",
    "https://argus.pw",
    "https://www.argus.pw",
  ];
};

export const ALLOWED_ORIGINS = parseAllowedOrigins();

export const MIDDY_CORS_CONFIG: Options = {
  origins: ALLOWED_ORIGINS,
  credentials: true,
  methods: "POST,OPTIONS",
  headers: ALLOWED_HEADERS.join(","),
};

export const WARMUP_EVENT = {
  source: "serverless-plugin-warmup",
  event: {
    source: "warmup",
    type: "keepalive",
  },
};

export const AWS_SECRETS_REQUIRED_KEYS: string[] = [
  "ENCRYPTION_KEY", // AES-GCM key for TCP blob decryption
  "HMAC_KEY", // HMAC key for signature validation
];

export const ERROR_STRINGS = {
  SECRETS_MANAGER_FAILED: "Failed to retrieve secrets from Secrets Manager",
  KEY_ARN_NOT_SET: "Environment variables SECRET_KEY_ARN must be set",
  CANNOT_PARSE_JSON: "Cannot Parse JSON Data",
  CANNOT_DECRYPT: "Cannot Decrypt Payload",
  CANNOT_VERIFY_SIGNATURE: "Cannot Verify Signature",
};

export const SECRET_KEY_ARN: string | undefined = process.env.SECRET_KEY_ARN;
export const POWERTOOLS_METRICS_NAMESPACE: string | undefined =
  process.env.POWERTOOLS_METRICS_NAMESPACE;
export const POWERTOOLS_SERVICE_NAME: string | undefined =
  process.env.POWERTOOLS_SERVICE_NAME;
