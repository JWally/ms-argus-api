// src/config/env.ts
// AR-52: Updated to use DynamoDB session cache instead of Redis
/**
 * Environment variable validation and typing.
 * Validates all required environment variables at startup and
 * provides type-safe access to configuration values.
 */

/**
 * Base environment configuration shared by all Lambda handlers
 */
export interface BaseEnvConfig {
  SESSION_CACHE_TABLE: string;
  PROFILES_TABLE: string;
  TIER1_INDEX_TABLE: string;
  TIER2_BUCKETS_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

/**
 * Environment configuration for the Matching Worker Lambda
 * AR-57: Added OBSERVATIONS_STREAM_NAME for analytics
 */
export interface MatchingWorkerEnvConfig extends BaseEnvConfig {
  PROFILE_QUEUE_URL: string;
  OBSERVATIONS_STREAM_NAME?: string; // Optional - analytics may not be deployed in all envs
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
    "SESSION_CACHE_TABLE",
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
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
    PROFILES_TABLE: process.env.PROFILES_TABLE!,
    TIER1_INDEX_TABLE: process.env.TIER1_INDEX_TABLE!,
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    PROFILE_QUEUE_URL: process.env.PROFILE_QUEUE_URL!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-matching",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
    // AR-57: Optional analytics stream
    OBSERVATIONS_STREAM_NAME: process.env.OBSERVATIONS_STREAM_NAME,
  };
}

/**
 * Validate and return environment configuration for the Profile Updater.
 * Throws an error listing all missing required variables.
 */
export function getProfileUpdaterEnv(): ProfileUpdaterEnvConfig {
  const required = [
    "SESSION_CACHE_TABLE",
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
    SESSION_CACHE_TABLE: process.env.SESSION_CACHE_TABLE!,
    PROFILES_TABLE: process.env.PROFILES_TABLE!,
    TIER1_INDEX_TABLE: process.env.TIER1_INDEX_TABLE!,
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-profile",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}
