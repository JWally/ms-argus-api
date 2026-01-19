// src/handlers/cardinality-recalc.ts
// AR-130: Daily Lambda to recalculate Tier2 bucket cardinalities
// Fixes drift from TTL-expired devices (ADD only increments, never decrements)
// AR-159: Refactored to process buckets in pages rather than collecting all keys first
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
 * Sleep utility for backoff
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

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
async function processBucket(
  tableName: string,
  bucketKey: string,
  ttl: number,
  maxRetries: number = 3,
): Promise<BucketResult> {
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
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
    } catch (error) {
      const isThrottling =
        error instanceof Error &&
        (error.name === "ProvisionedThroughputExceededException" ||
          error.name === "ThrottlingException");

      if (isThrottling && attempt < maxRetries - 1) {
        attempt++;
        // Exponential backoff: 100ms, 200ms, 400ms
        await sleep(Math.pow(2, attempt) * 100);
        continue;
      }
      throw error;
    }
  }

  // Should not reach here, but TypeScript needs a return
  throw new Error(
    `Failed to process bucket ${bucketKey} after ${maxRetries} retries`,
  );
}

/**
 * Cardinality Recalculation Lambda Handler
 * Triggered daily via EventBridge rule
 *
 * Scans all bucket_key partitions in Tier2Buckets table,
 * counts actual device items per bucket, and updates
 * the _stats item's cardinality to match actual count.
 */
export const handler: ScheduledHandler = async (event): Promise<void> => {
  const startTime = Date.now();
  const tableName = envConfig.TIER2_BUCKETS_TABLE;

  logger.info("Starting cardinality recalculation", {
    tableName,
    eventSource: event.source,
  });

  // TTL for stats items: 14 days (2x the bucket TTL of 7 days)
  const ttl = Math.floor(Date.now() / 1000) + 14 * 24 * 60 * 60;

  let bucketsProcessed = 0;
  let bucketsWithDrift = 0;
  let totalDriftMagnitude = 0;
  let errors = 0;

  try {
    // AR-159: Track processed buckets to handle duplicates across scan pages
    // (A bucket_key can appear multiple times in the scan if it has many device entries)
    const processedBuckets = new Set<string>();
    let pagesProcessed = 0;

    // AR-159: Process bucket keys page by page to reduce memory usage
    for await (const pageKeys of scanBucketKeysPages(tableName)) {
      pagesProcessed++;

      // Process each bucket in this page
      for (const bucketKey of pageKeys) {
        // Skip if already processed in a previous page
        if (processedBuckets.has(bucketKey)) {
          continue;
        }
        processedBuckets.add(bucketKey);

        try {
          const result = await processBucket(tableName, bucketKey, ttl);
          bucketsProcessed++;

          if (result.driftCorrected) {
            bucketsWithDrift++;
            const drift = Math.abs(
              result.previousCardinality - result.actualCardinality,
            );
            totalDriftMagnitude += drift;

            logger.info("Corrected bucket cardinality drift", {
              bucketKey,
              previousCardinality: result.previousCardinality,
              actualCardinality: result.actualCardinality,
              drift,
            });
          }
        } catch (error) {
          errors++;
          logger.error("Failed to process bucket", {
            bucketKey,
            error,
          });
          // Continue processing other buckets
        }
      }

      // Log progress after each page
      logger.info("Completed processing page", {
        page: pagesProcessed,
        totalBucketsProcessed: bucketsProcessed,
        bucketsWithDrift,
        errors,
      });
    }

    // Emit metrics
    metrics.addMetric("BucketsProcessed", MetricUnit.Count, bucketsProcessed);
    metrics.addMetric("BucketsWithDrift", MetricUnit.Count, bucketsWithDrift);
    metrics.addMetric(
      "TotalDriftMagnitude",
      MetricUnit.Count,
      totalDriftMagnitude,
    );
    metrics.addMetric("ProcessingErrors", MetricUnit.Count, errors);
    // AR-159: Track pagination metrics
    metrics.addMetric("PagesProcessed", MetricUnit.Count, pagesProcessed);

    const duration = Date.now() - startTime;
    metrics.addMetric("RecalcDuration", MetricUnit.Milliseconds, duration);

    logger.info("Cardinality recalculation complete", {
      bucketsProcessed,
      bucketsWithDrift,
      totalDriftMagnitude,
      errors,
      pagesProcessed,
      durationMs: duration,
    });
  } finally {
    metrics.publishStoredMetrics();
  }
};
