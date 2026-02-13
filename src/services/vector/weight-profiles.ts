/**
 * NSGA-II optimized per-OS weight profiles for v13 weighted embeddings.
 *
 * Each OS gets section-level weights derived from multi-objective optimization
 * (minimizing collision rate + volatility). Weights are expanded from 25 section
 * values to 512 per-dimension weights matching the v12 embedding layout.
 *
 * Section layout must match embedding.ts (v12 — v9_512):
 *   [0-67]    cssMedia        [68-101]  css           [102-134] screen
 *   [135-158] htmlElement     [159-166] maths         [167-174] windowFeatures
 *   [175-182] svg             [183-190] intl          [191-197] canvas_other
 *   [198]     canvas_198      [199-210] canvas_rest   [211-226] webgl
 *   [227-234] audio           [235-250] clientRects   [251-266] gpu_renderer
 *   [267-269] hw_scalars      [270-285] screen_dims   [286-293] platform
 *   [294-309] user_agent      [310]     hw2           [311-315] network
 *   [316-340] timezone        [341-345] privacy_flags [346-379] features_hash
 *   [380-511] fuzzy_hash
 *
 * @module services/vector/weight-profiles
 */

import type { OsCategory } from "./os-detection";

/** Section boundary definition matching the v12 embedding layout. */
interface Section {
  readonly name: string;
  readonly start: number;
  readonly end: number;
}

/** 25 sections covering all 512 dimensions. */
const SECTIONS: readonly Section[] = [
  { name: "cssMedia", start: 0, end: 67 },
  { name: "css", start: 68, end: 101 },
  { name: "screen", start: 102, end: 134 },
  { name: "htmlElement", start: 135, end: 158 },
  { name: "maths", start: 159, end: 166 },
  { name: "windowFeatures", start: 167, end: 174 },
  { name: "svg", start: 175, end: 182 },
  { name: "intl", start: 183, end: 190 },
  { name: "canvas_other", start: 191, end: 197 },
  { name: "canvas_198", start: 198, end: 198 },
  { name: "canvas_rest", start: 199, end: 210 },
  { name: "webgl", start: 211, end: 226 },
  { name: "audio", start: 227, end: 234 },
  { name: "clientRects", start: 235, end: 250 },
  { name: "gpu_renderer", start: 251, end: 266 },
  { name: "hw_scalars", start: 267, end: 269 },
  { name: "screen_dims", start: 270, end: 285 },
  { name: "platform", start: 286, end: 293 },
  { name: "user_agent", start: 294, end: 309 },
  { name: "hw2", start: 310, end: 310 },
  { name: "network", start: 311, end: 315 },
  { name: "timezone", start: 316, end: 340 },
  { name: "privacy_flags", start: 341, end: 345 },
  { name: "features_hash", start: 346, end: 379 },
  { name: "fuzzy_hash", start: 380, end: 511 },
] as const;

/**
 * Expand 25 section-level weights to a 512-dimensional per-dimension weight array.
 * Each dimension within a section gets the same weight value.
 */
function sectionWeightsToArray(sectionWeights: readonly number[]): number[] {
  const weights = new Array(512).fill(1.0);
  for (let i = 0; i < SECTIONS.length; i++) {
    const section = SECTIONS[i];
    for (let d = section.start; d <= section.end; d++) {
      weights[d] = sectionWeights[i];
    }
  }
  return weights;
}

// ─── Per-OS NSGA-II optimized section weights ────────────────────────────────

/** iOS: best-sum (9.2% coll / 13.2% vol) — boosts audio, UA; zeros canvas_198, webgl */
const IOS_WEIGHTS = sectionWeightsToArray([
  0.858, 0.62, 0.706, 1.158, 0.328, 1.774, 0.863, 0.945, 0.383, 0.0, 0.097,
  0.065, 4.128, 0.177, 0.22, 0.204, 1.0, 0.979, 4.908, 0.949, 0.738, 1.255,
  1.171, 1.092, 0.746,
]);

/** Android: best-sum (4.3% coll / 11.6% vol) — boosts svg, gpu; zeros htmlElement */
const ANDROID_WEIGHTS = sectionWeightsToArray([
  1.005, 0.999, 1.05, 0.0, 1.014, 1.064, 1.694, 0.904, 1.102, 1.193, 1.089,
  0.774, 0.902, 0.847, 1.246, 0.472, 0.012, 0.688, 1.026, 0.502, 0.849, 0.655,
  0.649, 0.999, 0.485,
]);

/** Windows: best coll≤6% (4.5% coll / 23.5% vol) — boosts screenDims, windowFeatures, css */
const WINDOWS_WEIGHTS = sectionWeightsToArray([
  0.0, 3.54, 3.704, 1.16, 2.186, 3.976, 1.165, 2.444, 1.513, 3.165, 0.975,
  3.329, 2.888, 3.803, 3.418, 1.027, 4.633, 1.139, 0.309, 2.872, 2.424, 2.483,
  1.425, 0.56, 0.989,
]);

/** Mac: best-sum (31.3% coll / 10.5% vol) — boosts svg, htmlElement, screen */
const MAC_WEIGHTS = sectionWeightsToArray([
  2.015, 3.809, 4.715, 4.832, 0.134, 3.115, 5.0, 0.381, 4.463, 3.007, 3.996,
  1.407, 0.52, 1.562, 2.636, 2.654, 0.466, 2.235, 3.959, 2.357, 4.604, 2.273,
  1.733, 2.857, 1.499,
]);

/** Linux: baseline weights (all 1.0) — small sample, no optimization needed */
const LINUX_WEIGHTS = new Array(512).fill(1.0);

/** Per-OS weight arrays keyed by OsCategory. */
const OS_WEIGHTS: Record<OsCategory, number[]> = {
  ios: IOS_WEIGHTS,
  android: ANDROID_WEIGHTS,
  windows: WINDOWS_WEIGHTS,
  mac: MAC_WEIGHTS,
  linux: LINUX_WEIGHTS,
};

/** Per-OS score thresholds. Initially uniform at 0.96; tune independently after deployment. */
const OS_THRESHOLDS: Record<OsCategory, number> = {
  ios: 0.96,
  android: 0.96,
  windows: 0.96,
  mac: 0.96,
  linux: 0.96,
};

/** Weight profile for an OS category. */
export interface WeightProfile {
  /** 512-dimensional per-dimension weight array */
  weights: number[];
  /** Score threshold for this OS */
  threshold: number;
}

/**
 * Get the NSGA-II weight profile for a given OS category.
 *
 * @param os - OS category from detectOS()
 * @returns Weight profile with per-dimension weights and score threshold
 */
export function getWeightProfile(os: OsCategory): WeightProfile {
  return {
    weights: OS_WEIGHTS[os],
    threshold: OS_THRESHOLDS[os],
  };
}
