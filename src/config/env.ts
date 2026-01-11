// src/config/env.ts
/**
 * Environment variable validation and typing.
 * Validates all required environment variables at startup and
 * provides type-safe access to configuration values.
 */

/**
 * Base environment configuration shared by all Lambda handlers
 */
export interface BaseEnvConfig {
  REDIS_ENDPOINT: string;
  REDIS_PORT: number;
  PROFILES_TABLE: string;
  TIER1_INDEX_TABLE: string;
  TIER2_BUCKETS_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

/**
 * Environment configuration for the Matching Worker Lambda
 */
export interface MatchingWorkerEnvConfig extends BaseEnvConfig {
  PROFILE_QUEUE_URL: string;
}

/**
 * Environment configuration for the Profile Updater Lambda
 */
export type ProfileUpdaterEnvConfig = BaseEnvConfig;

/**
 * Validate and return environment configuration for the Matching Worker.
 * Throws an error listing all missing required variables.
 */
export function getMatchingWorkerEnv(): MatchingWorkerEnvConfig {
  const required = [
    "REDIS_ENDPOINT",
    "PROFILES_TABLE",
    "TIER1_INDEX_TABLE",
    "TIER2_BUCKETS_TABLE",
    "PROFILE_QUEUE_URL",
  ] as const;

  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }

  return {
    REDIS_ENDPOINT: process.env.REDIS_ENDPOINT!,
    REDIS_PORT: parseInt(process.env.REDIS_PORT || "6379", 10),
    PROFILES_TABLE: process.env.PROFILES_TABLE!,
    TIER1_INDEX_TABLE: process.env.TIER1_INDEX_TABLE!,
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    PROFILE_QUEUE_URL: process.env.PROFILE_QUEUE_URL!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-matching",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}

/**
 * Validate and return environment configuration for the Profile Updater.
 * Throws an error listing all missing required variables.
 */
export function getProfileUpdaterEnv(): ProfileUpdaterEnvConfig {
  const required = [
    "REDIS_ENDPOINT",
    "PROFILES_TABLE",
    "TIER1_INDEX_TABLE",
    "TIER2_BUCKETS_TABLE",
  ] as const;

  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }

  return {
    REDIS_ENDPOINT: process.env.REDIS_ENDPOINT!,
    REDIS_PORT: parseInt(process.env.REDIS_PORT || "6379", 10),
    PROFILES_TABLE: process.env.PROFILES_TABLE!,
    TIER1_INDEX_TABLE: process.env.TIER1_INDEX_TABLE!,
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-profile",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}
