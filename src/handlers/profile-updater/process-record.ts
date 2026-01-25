/**
 * Profile updater SQS record processing.
 *
 * Handles profile update messages from the matching worker, applying
 * mutation gating and drift detection before persisting profile changes.
 * @module
 */
import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { ProfileService, ProfileUpdatePayload } from "../../services/profile";
import { normalizeFingerprint } from "../../helpers/normalize-fingerprint";

/** Result of processing a profile update request. */
export interface ProfileResult {
  /** Whether the update was skipped */
  skipped: boolean;
  /** Reason for skipping: 'mutation_gate' or 'no_drift' */
  reason?: string;
  /** Number of tier-1 index writes performed */
  tier1Writes?: number;
  /** Number of tier-2 bucket writes performed */
  tier2Writes?: number;
}

/**
 * Record metrics when profile update is skipped.
 *
 * Emits appropriate CloudWatch metric based on skip reason.
 *
 * @param result - Profile update result with skip reason
 * @param deviceId - Device ID for logging context
 * @param deps - Logger and metrics dependencies
 */
function recordSkipMetrics(
  result: ProfileResult,
  deviceId: string,
  deps: { logger: Logger; metrics: Metrics },
): void {
  if (result.reason === "mutation_gate") {
    deps.metrics.addMetric("MutationGateSkip", MetricUnit.Count, 1);
    deps.logger.info("Skipping update - recently updated", {
      device_id: deviceId,
    });
  } else if (result.reason === "no_drift") {
    deps.metrics.addMetric("NoDriftSkip", MetricUnit.Count, 1);
    if (result.tier2Writes) {
      deps.metrics.addMetric(
        "Tier2BucketWrites",
        MetricUnit.Count,
        result.tier2Writes,
      );
    }
    deps.logger.info("Skipping update - no significant drift", {
      device_id: deviceId,
      tier2Writes: result.tier2Writes,
    });
  }
}

/**
 * Record metrics after successful profile write.
 *
 * Emits index write counts and duration to CloudWatch.
 *
 * @param result - Profile update result with write counts
 * @param deviceId - Device ID for logging context
 * @param duration - Processing duration in milliseconds
 * @param deps - Logger and metrics dependencies
 */
function recordWriteMetrics(
  result: ProfileResult,
  deviceId: string,
  duration: number,
  deps: { logger: Logger; metrics: Metrics },
): void {
  deps.metrics.addMetric("ProfileWrite", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "Tier1IndexWrites",
    MetricUnit.Count,
    result.tier1Writes ?? 0,
  );
  deps.metrics.addMetric(
    "Tier2BucketWrites",
    MetricUnit.Count,
    result.tier2Writes ?? 0,
  );
  deps.metrics.addMetric(
    "ProfileUpdateDuration",
    MetricUnit.Milliseconds,
    duration,
  );
  deps.logger.info("Profile update complete", {
    device_id: deviceId,
    duration,
    tier1Writes: result.tier1Writes,
    tier2Writes: result.tier2Writes,
  });
}

/**
 * Process a single profile update SQS record.
 *
 * Parses the payload, normalizes the fingerprint, and delegates to
 * ProfileService. Handles mutation gating (skips recently updated profiles)
 * and drift detection (skips when no significant changes detected).
 *
 * @param record - SQS record containing profile update payload
 * @param service - Profile service instance
 * @param deps - Logger and metrics dependencies
 */
export async function processRecord(
  record: SQSRecord,
  service: ProfileService,
  deps: { logger: Logger; metrics: Metrics },
): Promise<void> {
  const startTime = Date.now();

  let rawPayload: ProfileUpdatePayload;
  try {
    rawPayload = JSON.parse(record.body);
  } catch (parseError) {
    deps.logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200),
    });
    deps.metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return;
  }

  const { device_id } = rawPayload;

  const payload: ProfileUpdatePayload = {
    ...rawPayload,
    fingerprint: normalizeFingerprint(
      rawPayload.fingerprint,
      rawPayload.sigint,
    ),
    raw_fingerprint: rawPayload.fingerprint,
  };

  deps.logger.info("Processing profile update", { device_id });

  const result = await service.processProfileUpdate(payload);

  if (result.skipped) {
    recordSkipMetrics(result, device_id, deps);
    return;
  }

  recordWriteMetrics(result, device_id, Date.now() - startTime, deps);
}
