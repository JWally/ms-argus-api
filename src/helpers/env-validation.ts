/**
 * Validates that required environment variables are set.
 * Throws an error with the list of missing variables if any are missing.
 *
 * @param required - Array of required environment variable names
 * @throws Error with list of missing variables if validation fails
 *
 * @example
 * ```typescript
 * // At module cold start
 * validateRequiredEnvVars(["TABLE_NAME", "QUEUE_URL"]);
 *
 * // With typed config
 * interface MyConfig {
 *   TABLE_NAME: string;
 *   OPTIONAL_VAR?: string;
 * }
 *
 * function getConfig(): MyConfig {
 *   validateRequiredEnvVars(["TABLE_NAME"]);
 *   return {
 *     TABLE_NAME: process.env.TABLE_NAME!,
 *     OPTIONAL_VAR: process.env.OPTIONAL_VAR,
 *   };
 * }
 * ```
 */
export function validateRequiredEnvVars(required: readonly string[]): void {
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(", ")}`,
    );
  }
}
