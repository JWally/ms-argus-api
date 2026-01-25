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
 */
export interface MatchingWorkerEnvConfig extends BaseEnvConfig {
  PROFILE_QUEUE_URL: string;
  SESSION_PAYLOAD_TABLE: string;
  OBSERVATIONS_STREAM_NAME?: string; // Optional - analytics may not be deployed in all envs
}

/**
 * Environment configuration for the Profile Updater Lambda
 */
export type ProfileUpdaterEnvConfig = BaseEnvConfig;

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
 * Build environment configuration with validation
 * @param required - Required environment variable names
 * @param serviceName - Default service name for Powertools
 * @param optional - Optional environment variable names
 * @returns Validated environment configuration
 * @throws Error if required variables are missing
 */
function buildEnvConfig<T>(
  required: readonly string[],
  serviceName: string,
  optional?: readonly string[],
): T {
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }
  const result: Record<string, string | undefined> = {};
  for (const key of required) result[key] = process.env[key]!;
  result.POWERTOOLS_SERVICE_NAME =
    process.env.POWERTOOLS_SERVICE_NAME || serviceName;
  result.POWERTOOLS_METRICS_NAMESPACE =
    process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus";
  if (optional) for (const key of optional) result[key] = process.env[key];
  return result as T;
}

/**
 * Get and validate environment configuration for Matching Worker
 * @returns Validated MatchingWorkerEnvConfig
 * @throws Error if required environment variables are missing
 */
export function getMatchingWorkerEnv(): MatchingWorkerEnvConfig {
  return buildEnvConfig<MatchingWorkerEnvConfig>(
    [
      "SESSION_CACHE_TABLE",
      "SESSION_PAYLOAD_TABLE",
      "PROFILES_TABLE",
      "TIER1_INDEX_TABLE",
      "TIER2_BUCKETS_TABLE",
      "PROFILE_QUEUE_URL",
    ],
    "argus-matching",
    ["OBSERVATIONS_STREAM_NAME"],
  );
}

/**
 * Get and validate environment configuration for Profile Updater
 * @returns Validated ProfileUpdaterEnvConfig
 * @throws Error if required environment variables are missing
 */
export function getProfileUpdaterEnv(): ProfileUpdaterEnvConfig {
  return buildEnvConfig<ProfileUpdaterEnvConfig>(
    [
      "SESSION_CACHE_TABLE",
      "PROFILES_TABLE",
      "TIER1_INDEX_TABLE",
      "TIER2_BUCKETS_TABLE",
    ],
    "argus-profile",
  );
}

/**
 * Get and validate environment configuration for Vector Worker
 * @returns Validated VectorWorkerEnvConfig
 * @throws Error if required environment variables are missing
 */
export function getVectorWorkerEnv(): VectorWorkerEnvConfig {
  return buildEnvConfig<VectorWorkerEnvConfig>(
    ["QDRANT_URL", "QDRANT_SECRET_ARN"],
    "argus-vector-worker",
  );
}
