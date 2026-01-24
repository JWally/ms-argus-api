import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

const TIER_METRICS: Record<number, string[]> = {
  0.5: ["Tier05Hit"],
  1: ["Tier1Hit"],
  2: ["Tier2Hit"],
  3: ["Tier3Hit"],
};

const NEW_DEVICE_METRICS = [
  "NewDevice",
  "NEW_DEVICE_RATE",
  "DeviceIdFormat_ulid",
];

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
