import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { ProfileService, ProfileUpdatePayload } from "../../services/profile";
import { normalizeFingerprint } from "../../helpers/normalize-fingerprint";

export interface ProfileResult {
  skipped: boolean;
  reason?: string;
  tier1Writes?: number;
  tier2Writes?: number;
}

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
