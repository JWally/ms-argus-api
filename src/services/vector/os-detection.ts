/**
 * OS detection from fingerprint data.
 *
 * Detects the operating system category from fingerprint fields
 * (platform string, then user agent fallback) for routing to
 * OS-specific vector collections with NSGA-II weight profiles.
 *
 * @module services/vector/os-detection
 */

import type { Fingerprint } from "../../types/fingerprint";

/**
 * Operating system categories for per-OS vector collections.
 * Each category gets its own NSGA-II-optimized weight profile and Qdrant collection.
 */
export type OsCategory = "ios" | "android" | "windows" | "mac" | "linux";

/**
 * Detect the OS category from a fingerprint.
 *
 * Detection priority:
 * 1. Platform string (most reliable for iOS — "iPhone" / "iPad")
 * 2. User agent regex fallback for Android, Windows, Mac, Linux/CrOS
 * 3. Defaults to "linux" (baseline weights, all 1.0) for unknown OS
 *
 * @param fingerprint - Normalized fingerprint with platform and user_agent fields
 * @returns OS category for collection routing
 */
export function detectOS(fingerprint: Fingerprint): OsCategory {
  const platform = fingerprint.platform;
  const ua = fingerprint.user_agent ?? "";

  // iOS: platform is most reliable (UA can be desktop-mode Safari)
  if (platform === "iPhone" || platform?.startsWith("iPad")) return "ios";

  // UA-based detection for remaining OS categories
  if (/Android/i.test(ua)) return "android";
  if (/Windows/i.test(ua)) return "windows";
  if (/Macintosh|Mac OS/i.test(ua)) return "mac";
  if (/Linux|CrOS/i.test(ua)) return "linux";

  // Unknown OS falls through to linux (baseline weights = all 1.0)
  return "linux";
}
