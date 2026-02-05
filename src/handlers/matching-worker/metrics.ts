/**
 * @fileoverview Metrics utilities for the matching worker.
 * Records tier hit and new device metrics to CloudWatch.
 * @module handlers/matching-worker/metrics
 */

import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { MatchTier } from "../../types/matching-tiers";

/**
 * Mapping of matching tiers to their CloudWatch metric names.
 * Uses MatchTier constants for type safety.
 * @internal
 */
const TIER_METRICS: Record<number, string[]> = {
  [MatchTier.IDENTITY]: ["Tier05Hit"],
  [MatchTier.HASH]: ["Tier1Hit"],
  [MatchTier.SIMHASH]: ["Tier15Hit"],
  [MatchTier.VECTOR]: ["Tier2Hit"],
};

/**
 * Metrics emitted when a new device is created.
 * Includes rate tracking and device ID format verification.
 * @internal
 */
const NEW_DEVICE_METRICS = [
  "NewDevice",
  "NEW_DEVICE_RATE",
  "DeviceIdFormat_ulid",
];

/**
 * Records CloudWatch metrics for a matching result.
 *
 * For existing devices: emits tier-specific hit metrics (Tier05Hit, Tier1Hit, etc.)
 * For new devices: emits NewDevice, NEW_DEVICE_RATE, and DeviceIdFormat_ulid metrics
 *
 * @param tier - The matching tier that produced the result (0.5, 1, 2, or 3)
 * @param isNewDevice - Whether this match resulted in a new device creation
 * @param metrics - AWS Powertools Metrics instance
 *
 * @example
 * ```typescript
 * recordTierMetric(1, false, metrics); // Emits Tier1Hit
 * recordTierMetric(0, true, metrics);  // Emits NewDevice, NEW_DEVICE_RATE, DeviceIdFormat_ulid
 * ```
 */
export function recordTierMetric(
  tier: number,
  isNewDevice: boolean,
  metrics: Metrics,
): void {
  const names = isNewDevice ? NEW_DEVICE_METRICS : (TIER_METRICS[tier] ?? []);
  for (const name of names) {
    metrics.addMetric(name, MetricUnit.Count, 1);
  }
}
