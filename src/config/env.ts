// src/config/env.ts
// AR-52: Updated to use DynamoDB session cache instead of Redis
// Vector worker env config added for ms-argus-vector integration
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
 * AR-XXX: Added SESSION_PAYLOAD_TABLE for full payload storage (gRPC stub)
 */
export interface MatchingWorkerEnvConfig extends BaseEnvConfig {
  PROFILE_QUEUE_URL: string;
  SESSION_PAYLOAD_TABLE: string; // AR-XXX: Full payload storage for gRPC stub
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
    "SESSION_PAYLOAD_TABLE",
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
    SESSION_PAYLOAD_TABLE: process.env.SESSION_PAYLOAD_TABLE!,
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

/**
 * Environment configuration for the Vector Worker Lambda
 * Requires access to QDrant via the ms-argus-vector VPC
 */
export interface VectorWorkerEnvConfig {
  QDRANT_URL: string;
  QDRANT_SECRET_ARN: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

/**
 * Validate and return environment configuration for the Vector Worker.
 * Throws an error listing all missing required variables.
 */
export function getVectorWorkerEnv(): VectorWorkerEnvConfig {
  const required = ["QDRANT_URL", "QDRANT_SECRET_ARN"] as const;

  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }

  return {
    QDRANT_URL: process.env.QDRANT_URL!,
    QDRANT_SECRET_ARN: process.env.QDRANT_SECRET_ARN!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-vector-worker",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}
