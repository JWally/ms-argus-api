/**
 * Collection router for per-OS vector collections.
 *
 * Routes fingerprints to the appropriate OS-specific Qdrant collection
 * with corresponding NSGA-II weight profile and score threshold.
 *
 * Collection naming: `{prefix}_{os}` (e.g., "fp_v13_ios", "fp_v13_android")
 *
 * @module services/vector/collection-router
 */

import type { Fingerprint } from "../../types/fingerprint";
import { detectOS, type OsCategory } from "./os-detection";
import { getWeightProfile } from "./weight-profiles";

/** Result of routing a fingerprint to its OS-specific collection. */
export interface RoutingResult {
  /** Detected OS category */
  os: OsCategory;
  /** Target Qdrant collection name (e.g., "fp_v13_ios") */
  collection: string;
  /** 512-dimensional per-dimension weights for weighted embedding */
  weights: number[];
  /** Score threshold for this OS */
  threshold: number;
}

/**
 * Route a fingerprint to its OS-specific collection with weight profile.
 *
 * @param fingerprint - Normalized fingerprint
 * @param prefix - Collection name prefix (e.g., "fp_v13")
 * @returns Routing result with collection name, weights, and threshold
 */
export function routeFingerprint(
  fingerprint: Fingerprint,
  prefix: string,
): RoutingResult {
  const os = detectOS(fingerprint);
  const profile = getWeightProfile(os);

  return {
    os,
    collection: `${prefix}_${os}`,
    weights: profile.weights,
    threshold: profile.threshold,
  };
}
