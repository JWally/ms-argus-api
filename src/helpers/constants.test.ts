import { describe, it, expect } from "vitest";
import {
  SESSION_TTL_SECONDS,
  TIER2_TIMEOUT_MS,
  PROFILE_TTL_DAYS,
  SIMHASH_CONFIG,
  AWS_SECRETS_REQUIRED_KEYS,
  ERROR_STRINGS,
  FNV1A_OFFSET_BASIS,
  FNV1A_PRIME,
  KEY_CACHE_DURATION,
  API_KEYS_CACHE_TTL,
  SESSION_PAYLOAD_TTL_SECONDS,
  TIER2_BUCKET_LIMIT,
  TIER2_HIGH_CARDINALITY_THRESHOLD,
  TIER2_CARDINALITY_PENALTY,
  TIER2_STATS_SK,
  PRIVACY_BROWSER_PENALTY,
  PRIVATE_BROWSING_PENALTY,
  TIER2_BUCKET_TTL_DAYS,
  SESSION_ANCHOR_VALIDITY_SECONDS,
  SESSION_ANCHOR_CLEANUP_TTL_SECONDS,
  IP_UA_ANCHOR_VALIDITY_SECONDS,
  MUTATION_GATE_TTL_SECONDS,
  DEDUPE_CACHE_MAX_ENTRIES,
  DEDUPE_CACHE_TTL_MS,
} from "./constants";

describe("SESSION_TTL_SECONDS", () => {
  it("should be 900 seconds (15 minutes)", () => {
    expect(SESSION_TTL_SECONDS).toBe(900);
  });
});

describe("TIER2_TIMEOUT_MS", () => {
  it("should be 500ms", () => {
    expect(TIER2_TIMEOUT_MS).toBe(500);
  });
});

describe("PROFILE_TTL_DAYS", () => {
  it("should be 60 days", () => {
    expect(PROFILE_TTL_DAYS).toBe(60);
  });
});

describe("SIMHASH_CONFIG", () => {
  it("should have correct structure with all required fields", () => {
    expect(SIMHASH_CONFIG).toHaveProperty("NUM_BANDS");
    expect(SIMHASH_CONFIG).toHaveProperty("BITS_PER_BAND");
    expect(SIMHASH_CONFIG).toHaveProperty("HAMMING_THRESHOLD");
    expect(SIMHASH_CONFIG).toHaveProperty("MIN_BANDS_MATCH");
    expect(SIMHASH_CONFIG).toHaveProperty("BAND_TTL_DAYS");
    expect(SIMHASH_CONFIG).toHaveProperty("PER_BAND_LIMIT");
    expect(SIMHASH_CONFIG).toHaveProperty("MAX_CANDIDATES");
    expect(SIMHASH_CONFIG).toHaveProperty("RECENCY_WINDOW_DAYS");
  });

  it("should have NUM_BANDS = 16 (for 256-bit hashes)", () => {
    expect(SIMHASH_CONFIG.NUM_BANDS).toBe(16);
  });

  it("should have BITS_PER_BAND = 16", () => {
    expect(SIMHASH_CONFIG.BITS_PER_BAND).toBe(16);
  });

  it("should have HAMMING_THRESHOLD = 16 (scaled for 256-bit)", () => {
    expect(SIMHASH_CONFIG.HAMMING_THRESHOLD).toBe(16);
  });

  it("should satisfy NUM_BANDS * BITS_PER_BAND = 256 (total hash bits)", () => {
    expect(SIMHASH_CONFIG.NUM_BANDS * SIMHASH_CONFIG.BITS_PER_BAND).toBe(256);
  });

  it("should have TOTAL_BITS = 256", () => {
    expect(SIMHASH_CONFIG.TOTAL_BITS).toBe(256);
  });

  it("should have HEX_LENGTH = 64 (256 bits / 4 bits per hex char)", () => {
    expect(SIMHASH_CONFIG.HEX_LENGTH).toBe(64);
  });
});

describe("AWS_SECRETS_REQUIRED_KEYS", () => {
  it("should include ENCRYPTION_KEY", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toContain("ENCRYPTION_KEY");
  });

  it("should include HMAC_KEY", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toContain("HMAC_KEY");
  });

  it("should have exactly 2 required keys", () => {
    expect(AWS_SECRETS_REQUIRED_KEYS).toHaveLength(2);
  });
});

describe("ERROR_STRINGS", () => {
  it("should contain all expected error messages", () => {
    expect(ERROR_STRINGS).toHaveProperty("SECRETS_MANAGER_FAILED");
    expect(ERROR_STRINGS).toHaveProperty("KEY_ARN_NOT_SET");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_PARSE_JSON");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_DECRYPT");
    expect(ERROR_STRINGS).toHaveProperty("CANNOT_VERIFY_SIGNATURE");
  });

  it("should have descriptive error messages", () => {
    expect(ERROR_STRINGS.SECRETS_MANAGER_FAILED).toContain("Secrets Manager");
    expect(ERROR_STRINGS.CANNOT_PARSE_JSON).toContain("JSON");
  });
});

describe("remaining constants have correct values", () => {
  it("FNV1A_OFFSET_BASIS should be the standard value", () => {
    expect(FNV1A_OFFSET_BASIS).toBe(2166136261);
  });

  it("FNV1A_PRIME should be the standard value", () => {
    expect(FNV1A_PRIME).toBe(16777619);
  });

  it("KEY_CACHE_DURATION should be 15 minutes in ms", () => {
    expect(KEY_CACHE_DURATION).toBe(900000);
  });

  it("API_KEYS_CACHE_TTL should be 5 minutes in ms", () => {
    expect(API_KEYS_CACHE_TTL).toBe(300000);
  });

  it("SESSION_PAYLOAD_TTL_SECONDS should be 1800", () => {
    expect(SESSION_PAYLOAD_TTL_SECONDS).toBe(1800);
  });

  it("TIER2_BUCKET_LIMIT should be 1000", () => {
    expect(TIER2_BUCKET_LIMIT).toBe(1000);
  });

  it("TIER2_HIGH_CARDINALITY_THRESHOLD should be 500", () => {
    expect(TIER2_HIGH_CARDINALITY_THRESHOLD).toBe(500);
  });

  it("TIER2_CARDINALITY_PENALTY should be 0.3", () => {
    expect(TIER2_CARDINALITY_PENALTY).toBe(0.3);
  });

  it("TIER2_STATS_SK should be _stats", () => {
    expect(TIER2_STATS_SK).toBe("_stats");
  });

  it("PRIVACY_BROWSER_PENALTY should be 0 (disabled)", () => {
    expect(PRIVACY_BROWSER_PENALTY).toBe(0);
  });

  it("PRIVATE_BROWSING_PENALTY should be 0 (disabled)", () => {
    expect(PRIVATE_BROWSING_PENALTY).toBe(0);
  });

  it("TIER2_BUCKET_TTL_DAYS should be 7", () => {
    expect(TIER2_BUCKET_TTL_DAYS).toBe(7);
  });

  it("SESSION_ANCHOR_VALIDITY_SECONDS should be 600", () => {
    expect(SESSION_ANCHOR_VALIDITY_SECONDS).toBe(600);
  });

  it("SESSION_ANCHOR_CLEANUP_TTL_SECONDS should be 3600", () => {
    expect(SESSION_ANCHOR_CLEANUP_TTL_SECONDS).toBe(3600);
  });

  it("IP_UA_ANCHOR_VALIDITY_SECONDS should be 180", () => {
    expect(IP_UA_ANCHOR_VALIDITY_SECONDS).toBe(180);
  });

  it("MUTATION_GATE_TTL_SECONDS should be 3600", () => {
    expect(MUTATION_GATE_TTL_SECONDS).toBe(3600);
  });

  it("DEDUPE_CACHE_MAX_ENTRIES should be 30000", () => {
    expect(DEDUPE_CACHE_MAX_ENTRIES).toBe(30000);
  });

  it("DEDUPE_CACHE_TTL_MS should be 30000", () => {
    expect(DEDUPE_CACHE_TTL_MS).toBe(30000);
  });
});

describe("removed exports should not exist", () => {
  it("should not export SECURITY_KEY_NAME", async () => {
    const constants = await import("./constants");
    expect("SECURITY_KEY_NAME" in constants).toBe(false);
  });

  it("should not export DEFAULT_HEADERS", async () => {
    const constants = await import("./constants");
    expect("DEFAULT_HEADERS" in constants).toBe(false);
  });

  it("should not export ALLOWED_HEADERS", async () => {
    const constants = await import("./constants");
    expect("ALLOWED_HEADERS" in constants).toBe(false);
  });

  it("should not export ALLOWED_ORIGINS", async () => {
    const constants = await import("./constants");
    expect("ALLOWED_ORIGINS" in constants).toBe(false);
  });

  it("should not export MIDDY_CORS_CONFIG", async () => {
    const constants = await import("./constants");
    expect("MIDDY_CORS_CONFIG" in constants).toBe(false);
  });

  it("should not export WARMUP_EVENT", async () => {
    const constants = await import("./constants");
    expect("WARMUP_EVENT" in constants).toBe(false);
  });

  it("should not export SECRET_KEY_ARN", async () => {
    const constants = await import("./constants");
    expect("SECRET_KEY_ARN" in constants).toBe(false);
  });

  it("should not export POWERTOOLS_METRICS_NAMESPACE", async () => {
    const constants = await import("./constants");
    expect("POWERTOOLS_METRICS_NAMESPACE" in constants).toBe(false);
  });

  it("should not export POWERTOOLS_SERVICE_NAME", async () => {
    const constants = await import("./constants");
    expect("POWERTOOLS_SERVICE_NAME" in constants).toBe(false);
  });
});
