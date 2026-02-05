/**
 * @fileoverview Profile service module exports.
 *
 * Manages device profiles in DynamoDB including:
 * - Profile creation and updates
 * - Fingerprint drift detection
 * - Risk flag computation
 * - Index maintenance for matching lookups
 *
 * @module services/profile
 */

export * from "./types";
export * from "./profile-service";
export * from "./drift-detection";
export * from "./flag-computation";
export * from "./index-writers";
