/**
 * Lightweight User-Agent family extraction.
 *
 * Extracts browser family from User-Agent strings without external dependencies.
 * Used for statistical anomaly detection grouping.
 * @module services/cache/ua-parser
 */

/**
 * Known browser families in detection priority order.
 * Order matters: Edge must be checked before Chrome (Edge contains "Chrome").
 */
const UA_PATTERNS: [RegExp, string][] = [
  // Must check Edge before Chrome (Edge UA contains "Chrome")
  [/Edg(?:e|A|iOS)?\//, "Edge"],
  // Opera must be checked before Chrome (Opera UA contains "Chrome")
  [/OPR\/|Opera\//, "Opera"],
  // Mobile browsers (check before Safari/Chrome since they also contain those)
  [/SamsungBrowser\//, "Samsung"],
  [/UCBrowser\//, "UC"],
  // Standard browsers
  [/Firefox\//, "Firefox"],
  [/Chrome\//, "Chrome"],
  // Safari must be last among standard browsers (many UAs contain Safari)
  [/Safari\//, "Safari"],
  // Legacy IE
  [/MSIE |Trident\//, "IE"],
];

/**
 * Extract browser family from User-Agent string.
 *
 * Returns a normalized browser family name for grouping in statistical analysis.
 * Designed to be fast and dependency-free.
 *
 * @param userAgent - Raw User-Agent string from request
 * @returns Browser family name: "Chrome", "Firefox", "Safari", "Edge", "Opera", "IE", "Samsung", "UC", or "Unknown"
 *
 * @example
 * ```typescript
 * extractUaFamily("Mozilla/5.0 ... Chrome/120.0.0.0 Safari/537.36")
 * // Returns: "Chrome"
 *
 * extractUaFamily("Mozilla/5.0 ... Edg/120.0.0.0")
 * // Returns: "Edge"
 *
 * extractUaFamily("")
 * // Returns: "Unknown"
 * ```
 */
export function extractUaFamily(userAgent: string | undefined): string {
  if (!userAgent) {
    return "Unknown";
  }

  for (const [pattern, family] of UA_PATTERNS) {
    if (pattern.test(userAgent)) {
      return family;
    }
  }

  return "Unknown";
}
