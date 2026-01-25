/**
 * Tier-2 bucket cardinality processing.
 *
 * Handles individual bucket cardinality recalculation with retry logic
 * and exponential backoff for throttling scenarios.
 * @module
 */
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { sleep } from "../../helpers/sleep";
import {
  countBucketDevices,
  getCurrentCardinality,
  updateCardinality,
} from "./dynamo-ops";

/** Result of processing a single bucket's cardinality. */
interface BucketResult {
  /** Bucket key that was processed */
  bucketKey: string;
  /** Cardinality value before recalculation */
  previousCardinality: number;
  /** Actual device count from scan */
  actualCardinality: number;
  /** Whether drift was detected and corrected */
  driftCorrected: boolean;
}

export type { BucketResult };

/**
 * Check if error is a DynamoDB throttling error.
 *
 * @param error - Error to check
 * @returns True if throttling error
 */
function isThrottlingError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "ProvisionedThroughputExceededException" ||
      error.name === "ThrottlingException")
  );
}

/**
 * Check bucket cardinality and correct if drifted.
 *
 * @param ctx - Table name and DynamoDB client
 * @param bucketKey - Bucket key to check
 * @param ttl - TTL for cardinality record
 * @returns Bucket result with drift status
 */
async function checkAndCorrectBucket(
  ctx: { tableName: string; dynamodb: DynamoDBClient },
  bucketKey: string,
  ttl: number,
): Promise<BucketResult> {
  const { tableName, dynamodb } = ctx;
  const [currentCardinality, actualCount] = await Promise.all([
    getCurrentCardinality(tableName, bucketKey, dynamodb),
    countBucketDevices(tableName, bucketKey, dynamodb),
  ]);
  const driftCorrected = currentCardinality !== actualCount;
  if (driftCorrected) {
    await updateCardinality(
      { tableName, bucketKey, cardinality: actualCount, ttl },
      dynamodb,
    );
  }
  return {
    bucketKey,
    previousCardinality: currentCardinality,
    actualCardinality: actualCount,
    driftCorrected,
  };
}

/**
 * Process a bucket with exponential backoff retry.
 *
 * Attempts to check and correct bucket cardinality with automatic
 * retry on throttling. Backoff doubles on each retry (200ms, 400ms, 800ms).
 *
 * @param ctx - Table name and DynamoDB client
 * @param bucketKey - Bucket key to process
 * @param ttl - TTL for cardinality record
 * @param maxRetries - Maximum retry attempts (default 3)
 * @returns Bucket result with drift status
 * @throws Error after max retries exhausted
 */
export async function processBucket(
  ctx: { tableName: string; dynamodb: DynamoDBClient },
  bucketKey: string,
  ttl: number,
  maxRetries = 3,
): Promise<BucketResult> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await checkAndCorrectBucket(ctx, bucketKey, ttl);
    } catch (error) {
      if (isThrottlingError(error) && attempt < maxRetries - 1) {
        await sleep(Math.pow(2, attempt + 1) * 100);
        continue;
      }
      throw error;
    }
  }
  throw new Error(
    `Failed to process bucket ${bucketKey} after ${maxRetries} retries`,
  );
}
