/**
 * Environment variable validation and typing.
 * Validates all required environment variables at startup and provides
 * type-safe access to configuration values.
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
  for (const key of required) result[key] = process.env[key] as string;
  result.POWERTOOLS_SERVICE_NAME =
    process.env.POWERTOOLS_SERVICE_NAME || serviceName;
  result.POWERTOOLS_METRICS_NAMESPACE =
    process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus";
  if (optional) for (const key of optional) result[key] = process.env[key];
  return result as T;
}

/**
 * Environment configuration for the Integrity Archiver Lambda
 * (DynamoDB Streams → S3).
 */
export interface IntegrityArchiverEnvConfig {
  INTEGRITY_ARCHIVE_BUCKET: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

export function getIntegrityArchiverEnv(): IntegrityArchiverEnvConfig {
  return buildEnvConfig<IntegrityArchiverEnvConfig>(
    ["INTEGRITY_ARCHIVE_BUCKET"],
    "argus-integrity-archiver",
  );
}
