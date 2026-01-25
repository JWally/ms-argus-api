/**
 * Profile updater SQS record processing.
 *
 * Handles profile update messages from the matching worker, applying
 * mutation gating and drift detection before persisting profile changes.
 * Optionally queues vector upserts for Qdrant similarity search.
 * @module
 */
import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { ProfileService, ProfileUpdatePayload } from "../../services/profile";
import { normalizeFingerprint } from "../../helpers/normalize-fingerprint";
import {
  computeEmbedding,
  EMBEDDING_VERSION,
} from "../../services/vector/embedding";
import type { VectorUpsertMessage } from "../vector-worker/types";

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

/** Qdrant collection name for fingerprint vectors (256-dim, v2 embedding) */
const VECTOR_COLLECTION = "fingerprints_v2";

/**
 * Queue a vector upsert message for the vector worker.
 *
 * Computes the fingerprint embedding and sends it to the vector queue
 * for async processing by the vector worker → Qdrant.
 *
 * @param payload - Profile update payload with fingerprint
 * @param deps - Dependencies including SQS client
 */
async function queueVectorUpsert(
  payload: ProfileUpdatePayload,
  deps: {
    sqsClient: SQSClient;
    vectorQueueUrl: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<void> {
  const { device_id, fingerprint } = payload;

  try {
    // Compute embedding from fingerprint
    const embedding = computeEmbedding(fingerprint);

    // Build vector upsert message
    // Note: Qdrant requires numeric IDs, so we hash the device_id to a number
    // Using a simple hash - in production might want something more robust
    const numericId = hashDeviceId(device_id);

    const message: VectorUpsertMessage = {
      type: "upsert",
      device_id,
      vector: embedding.vector,
      collection: VECTOR_COLLECTION,
      payload: {
        device_id,
        embedding_version: EMBEDDING_VERSION,
        updated_at: new Date().toISOString(),
      },
    };

    // For Qdrant, we need to use a numeric ID
    // Override device_id in the message with the numeric hash
    const qdrantMessage = {
      ...message,
      device_id: numericId.toString(),
    };

    await deps.sqsClient.send(
      new SendMessageCommand({
        QueueUrl: deps.vectorQueueUrl,
        MessageBody: JSON.stringify(qdrantMessage),
      }),
    );

    deps.metrics.addMetric("VectorUpsertQueued", MetricUnit.Count, 1);
    deps.logger.debug("Vector upsert queued", {
      device_id,
      numeric_id: numericId,
      dimensions: embedding.dimensions,
    });
  } catch (error) {
    // Log but don't fail the profile update if vector queueing fails
    deps.logger.warn("Failed to queue vector upsert", {
      device_id,
      error: error instanceof Error ? error.message : "Unknown error",
    });
    deps.metrics.addMetric("VectorUpsertQueueError", MetricUnit.Count, 1);
  }
}

/**
 * Hash a device ID (ULID string) to a numeric ID for Qdrant.
 * Uses a simple FNV-1a hash to get a stable numeric representation.
 */
function hashDeviceId(deviceId: string): number {
  let hash = 2166136261; // FNV offset basis
  for (let i = 0; i < deviceId.length; i++) {
    hash ^= deviceId.charCodeAt(i);
    hash = Math.imul(hash, 16777619); // FNV prime
  }
  // Convert to positive integer
  return hash >>> 0;
}

/** Dependencies for processRecord */
interface ProcessRecordDeps {
  logger: Logger;
  metrics: Metrics;
  /** Optional: SQS client for vector queue. If null, vector upserts are disabled. */
  sqsClient: SQSClient | null;
  /** Optional: Vector queue URL. Required if sqsClient is provided. */
  vectorQueueUrl?: string;
}

/**
 * Process a single profile update SQS record.
 *
 * Parses the payload, normalizes the fingerprint, and delegates to
 * ProfileService. Handles mutation gating (skips recently updated profiles)
 * and drift detection (skips when no significant changes detected).
 *
 * Optionally queues vector upserts for Qdrant if vector queue is configured.
 *
 * @param record - SQS record containing profile update payload
 * @param service - Profile service instance
 * @param deps - Logger, metrics, and optional vector queue dependencies
 */
export async function processRecord(
  record: SQSRecord,
  service: ProfileService,
  deps: ProcessRecordDeps,
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

  // Queue vector upsert if enabled (vector queue is configured)
  if (deps.sqsClient && deps.vectorQueueUrl) {
    await queueVectorUpsert(payload, {
      sqsClient: deps.sqsClient,
      vectorQueueUrl: deps.vectorQueueUrl,
      logger: deps.logger,
      metrics: deps.metrics,
    });
  }
}
