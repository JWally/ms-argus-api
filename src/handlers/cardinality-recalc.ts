// src/handlers/cardinality-recalc.ts
// Daily Lambda to recalculate Tier2 bucket cardinalities
// Fixes drift from TTL-expired devices (ADD only increments, never decrements)
import { ScheduledHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  DynamoDBClient,
  ScanCommand,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { TIER2_STATS_SK } from "../helpers/constants";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import { sleep } from "../helpers/sleep";

/**
 * Environment configuration for the Cardinality Recalc Lambda
 */
interface CardinalityRecalcEnvConfig {
  TIER2_BUCKETS_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

/**
 * Validate and return environment configuration.
 * Throws an error if required variables are missing.
 */
function getCardinalityRecalcEnv(): CardinalityRecalcEnvConfig {
  validateRequiredEnvVars(["TIER2_BUCKETS_TABLE"]);

  return {
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-cardinality-recalc",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}

// Validate environment variables at module load (cold start)
const envConfig: CardinalityRecalcEnvConfig = getCardinalityRecalcEnv();

// Powertools
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK client (reused across invocations)
const dynamodb = new DynamoDBClient({});

/**
 * Result of processing a single bucket
 */
interface BucketResult {
  bucketKey: string;
  previousCardinality: number;
  actualCardinality: number;
  driftCorrected: boolean;
}

/**
 * AR-159: Async generator to scan bucket_key values page by page
 * Yields unique bucket keys from each page, processing as we go
 * This reduces peak memory usage compared to collecting all keys first
 */
async function* scanBucketKeysPages(
  tableName: string,
): AsyncGenerator<Set<string>, void, undefined> {
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  let pageNumber = 0;

  do {
    pageNumber++;
    const response = await dynamodb.send(
      new ScanCommand({
        TableName: tableName,
        ProjectionExpression: "bucket_key",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    // Extract unique bucket keys from this page
    const pageKeys = new Set<string>();
    for (const item of response.Items || []) {
      if (item.bucket_key?.S) {
        pageKeys.add(item.bucket_key.S);
      }
    }

    logger.debug("Scanned bucket keys page", {
      pageNumber,
      keysInPage: pageKeys.size,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    yield pageKeys;

    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);
}

/**
 * Count actual device items in a bucket (excluding _stats SK)
 */
async function countBucketDevices(
  tableName: string,
  bucketKey: string,
): Promise<number> {
  let count = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const response = await dynamodb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: "bucket_key = :pk",
        FilterExpression: "device_id <> :stats_sk",
        ExpressionAttributeValues: {
          ":pk": { S: bucketKey },
          ":stats_sk": { S: TIER2_STATS_SK },
        },
        Select: "COUNT",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    count += response.Count || 0;
    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);

  return count;
}

/**
 * Get current cardinality from _stats item
 * Returns 0 if _stats item doesn't exist
 */
async function getCurrentCardinality(
  tableName: string,
  bucketKey: string,
): Promise<number> {
  const response = await dynamodb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: "bucket_key = :pk AND device_id = :sk",
      ExpressionAttributeValues: {
        ":pk": { S: bucketKey },
        ":sk": { S: TIER2_STATS_SK },
      },
      ProjectionExpression: "cardinality",
    }),
  );

  const item = response.Items?.[0];
  if (item?.cardinality?.N) {
    return parseInt(item.cardinality.N, 10);
  }
  return 0;
}

/**
 * Update cardinality to match actual count
 * Uses SET instead of ADD to overwrite with correct value
 */
async function updateCardinality(
  tableName: string,
  bucketKey: string,
  cardinality: number,
  ttl: number,
): Promise<void> {
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: tableName,
      Key: {
        bucket_key: { S: bucketKey },
        device_id: { S: TIER2_STATS_SK },
      },
      UpdateExpression: "SET cardinality = :c, #ttl = :ttl",
      ExpressionAttributeNames: {
        "#ttl": "ttl",
      },
      ExpressionAttributeValues: {
        ":c": { N: String(cardinality) },
        ":ttl": { N: String(ttl) },
      },
    }),
  );
}

/**
 * Process a single bucket with retry logic for throttling
 */
function isThrottlingError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === "ProvisionedThroughputExceededException" ||
      error.name === "ThrottlingException")
  );
}

async function checkAndCorrectBucket(
  tableName: string,
  bucketKey: string,
  ttl: number,
): Promise<BucketResult> {
  const [currentCardinality, actualCount] = await Promise.all([
    getCurrentCardinality(tableName, bucketKey),
    countBucketDevices(tableName, bucketKey),
  ]);
  const driftCorrected = currentCardinality !== actualCount;
  if (driftCorrected) {
    await updateCardinality(tableName, bucketKey, actualCount, ttl);
  }
  return {
    bucketKey,
    previousCardinality: currentCardinality,
    actualCardinality: actualCount,
    driftCorrected,
  };
}

async function processBucket(
  tableName: string,
  bucketKey: string,
  ttl: number,
  maxRetries = 3,
): Promise<BucketResult> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await checkAndCorrectBucket(tableName, bucketKey, ttl);
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

interface RecalcStats {
  bucketsProcessed: number;
  bucketsWithDrift: number;
  totalDriftMagnitude: number;
  errors: number;
  pagesProcessed: number;
}

async function processBucketPage(
  pageKeys: Set<string>,
  ctx: { processed: Set<string>; tableName: string; ttl: number },
  stats: RecalcStats,
): Promise<void> {
  const { processed: processedBuckets, tableName, ttl } = ctx;
  for (const bucketKey of pageKeys) {
    if (processedBuckets.has(bucketKey)) continue;
    processedBuckets.add(bucketKey);
    try {
      const result = await processBucket(tableName, bucketKey, ttl);
      stats.bucketsProcessed++;
      if (result.driftCorrected) {
        stats.bucketsWithDrift++;
        stats.totalDriftMagnitude += Math.abs(
          result.previousCardinality - result.actualCardinality,
        );
        logger.info("Corrected bucket cardinality drift", {
          bucketKey,
          previousCardinality: result.previousCardinality,
          actualCardinality: result.actualCardinality,
        });
      }
    } catch (error) {
      stats.errors++;
      logger.error("Failed to process bucket", { bucketKey, error });
    }
  }
}

async function processAllBuckets(
  tableName: string,
  ttl: number,
): Promise<RecalcStats> {
  const stats: RecalcStats = {
    bucketsProcessed: 0,
    bucketsWithDrift: 0,
    totalDriftMagnitude: 0,
    errors: 0,
    pagesProcessed: 0,
  };
  const ctx = { processed: new Set<string>(), tableName, ttl };
  for await (const pageKeys of scanBucketKeysPages(tableName)) {
    stats.pagesProcessed++;
    await processBucketPage(pageKeys, ctx, stats);
    logger.info("Completed processing page", {
      page: stats.pagesProcessed,
      totalBucketsProcessed: stats.bucketsProcessed,
      bucketsWithDrift: stats.bucketsWithDrift,
      errors: stats.errors,
    });
  }
  return stats;
}

function emitRecalcMetrics(stats: RecalcStats, duration: number): void {
  metrics.addMetric(
    "BucketsProcessed",
    MetricUnit.Count,
    stats.bucketsProcessed,
  );
  metrics.addMetric(
    "BucketsWithDrift",
    MetricUnit.Count,
    stats.bucketsWithDrift,
  );
  metrics.addMetric(
    "TotalDriftMagnitude",
    MetricUnit.Count,
    stats.totalDriftMagnitude,
  );
  metrics.addMetric("ProcessingErrors", MetricUnit.Count, stats.errors);
  metrics.addMetric("PagesProcessed", MetricUnit.Count, stats.pagesProcessed);
  metrics.addMetric("RecalcDuration", MetricUnit.Milliseconds, duration);
  logger.info("Cardinality recalculation complete", {
    ...stats,
    durationMs: duration,
  });
}

/** Cardinality Recalculation Lambda Handler - triggered daily via EventBridge */
export const handler: ScheduledHandler = async (event): Promise<void> => {
  const startTime = Date.now();
  const tableName = envConfig.TIER2_BUCKETS_TABLE;

  logger.info("Starting cardinality recalculation", {
    tableName,
    eventSource: event.source,
  });

  const ttl = Math.floor(Date.now() / 1000) + 14 * 24 * 60 * 60;
  try {
    const stats = await processAllBuckets(tableName, ttl);
    emitRecalcMetrics(stats, Date.now() - startTime);
  } finally {
    metrics.publishStoredMetrics();
  }
};
