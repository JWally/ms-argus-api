import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { sleep } from "../../helpers/sleep";
import {
  countBucketDevices,
  getCurrentCardinality,
  updateCardinality,
} from "./dynamo-ops";

interface BucketResult {
  bucketKey: string;
  previousCardinality: number;
  actualCardinality: number;
  driftCorrected: boolean;
}

export type { BucketResult };

function isThrottlingError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "ProvisionedThroughputExceededException" ||
      error.name === "ThrottlingException")
  );
}

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
