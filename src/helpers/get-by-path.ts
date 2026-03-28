/**
 * Utility for extracting values from nested objects using dot-path notation.
 *
 * @module helpers/get-by-path
 */

/**
 * Extract a value from a nested object using dot-path notation.
 *
 * @param obj - The object to extract from
 * @param path - Dot-separated path (e.g., "a.b.c")
 * @returns The value at the path, or undefined if not found
 *
 * @example
 * const data = { aws_cf: { ja4: "abc123" } };
 * getByPath(data, "aws_cf.ja4"); // "abc123"
 * getByPath(data, "aws_cf.ja3"); // undefined
 */
export function getByPath<T = unknown>(
  obj: Record<string, unknown> | undefined | null,
  path: string,
): T | undefined {
  if (!obj || !path) {
    return undefined;
  }

  const keys = path.split(".");
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current as T | undefined;
}
