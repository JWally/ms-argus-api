/**
 * Integrity-record TTL resolver.
 *
 * Default: 30 days. The integrity-results table is the live read
 * store for the dashboard's session inspector — 30 days of retention
 * lets a merchant inspect last-month sessions and lets support pull
 * up a session after a customer report. The S3 + Firehose archive
 * remains the source of truth past the TTL window.
 *
 * Override via the `INTEGRITY_TTL_SECONDS` env var when storage
 * cost matters more than retention (e.g. high-volume prod stages
 * keeping 7 days in DDB and pushing the rest into the archive).
 *
 * Extracted to its own module so it's directly unit-testable; the
 * value used to live inline in base-handler.ts where the env-read
 * happened at module load time.
 */

/** 30 days in seconds. Inlined as the literal so mutation testers can find boundary mutants. */
export const DEFAULT_INTEGRITY_TTL_SECONDS = 2_592_000;

/**
 * Resolve the TTL window in seconds. `env` is normally `process.env`,
 * passed in for testability. Non-numeric or non-positive values fall
 * back to the default — defensive against typos in stage config.
 *
 * `Number(undefined)` is `NaN`, `Number("")` is `0`, so a single
 * positive-finite check covers unset / empty / garbage / zero /
 * negative / Infinity in one branch (mutation-friendly: there are
 * no equivalent rewrites of an overlapping early-return).
 */
export function resolveIntegrityTtlSeconds(env: NodeJS.ProcessEnv): number {
  const n = Number(env.INTEGRITY_TTL_SECONDS);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_INTEGRITY_TTL_SECONDS;
  return n;
}
