/**
 * Cardinality recalculation orchestration.
 *
 * Coordinates scanning all tier-2 buckets and recalculating their
 * cardinality values to correct any drift from failed updates.
 * @module
 */
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { scanBucketKeysPages } from "./dynamo-ops";
import { processBucket } from "./bucket-processor";

/** Statistics from a cardinality recalculation run. */
export interface RecalcStats {
  /** Total buckets processed */
  bucketsProcessed: number;
  /** Buckets where drift was detected and corrected */
  bucketsWithDrift: number;
  /** Sum of absolute cardinality differences corrected */
  totalDriftMagnitude: number;
  /** Number of buckets that failed processing */
  errors: number;
  /** Number of DynamoDB scan pages processed */
  pagesProcessed: number;
}

/**
 * Process a page of bucket keys from scan results.
 *
 * @param pageKeys - Set of bucket keys from current scan page
 * @param ctx - Processing context with deduplication set
 * @param stats - Stats object to update
 * @param deps - DynamoDB client and logger
 */
async function processBucketPage(
  pageKeys: Set<string>,
  ctx: { processed: Set<string>; tableName: string; ttl: number },
  stats: RecalcStats,
  deps: { dynamodb: DynamoDBClient; logger: Logger },
): Promise<void> {
  const { processed: processedBuckets, tableName, ttl } = ctx;
  for (const bucketKey of pageKeys) {
    if (processedBuckets.has(bucketKey)) continue;
    processedBuckets.add(bucketKey);
    try {
      const result = await processBucket(
        { tableName, dynamodb: deps.dynamodb },
        bucketKey,
        ttl,
      );
      stats.bucketsProcessed++;
      if (result.driftCorrected) {
        stats.bucketsWithDrift++;
        stats.totalDriftMagnitude += Math.abs(
          result.previousCardinality - result.actualCardinality,
        );
        deps.logger.info("Corrected bucket cardinality drift", {
          bucketKey,
          previousCardinality: result.previousCardinality,
          actualCardinality: result.actualCardinality,
        });
      }
    } catch (error) {
      stats.errors++;
      deps.logger.error("Failed to process bucket", { bucketKey, error });
    }
  }
}

/**
 * Scan and process all tier-2 buckets for cardinality drift.
 *
 * Iterates through all bucket keys using paginated scans, checking
 * each bucket's cardinality against actual device count. Deduplicates
 * bucket keys across pages to avoid reprocessing.
 *
 * @param tableName - Tier-2 buckets DynamoDB table name
 * @param ttl - TTL for updated cardinality records
 * @param deps - DynamoDB client and logger
 * @returns Statistics from the recalculation run
 */
export async function processAllBuckets(
  tableName: string,
  ttl: number,
  deps: { dynamodb: DynamoDBClient; logger: Logger },
): Promise<RecalcStats> {
  const stats: RecalcStats = {
    bucketsProcessed: 0,
    bucketsWithDrift: 0,
    totalDriftMagnitude: 0,
    errors: 0,
    pagesProcessed: 0,
  };
  const ctx = { processed: new Set<string>(), tableName, ttl };
  for await (const pageKeys of scanBucketKeysPages(tableName, deps)) {
    stats.pagesProcessed++;
    await processBucketPage(pageKeys, ctx, stats, deps);
    deps.logger.info("Completed processing page", {
      page: stats.pagesProcessed,
      totalBucketsProcessed: stats.bucketsProcessed,
      bucketsWithDrift: stats.bucketsWithDrift,
      errors: stats.errors,
    });
  }
  return stats;
}

/**
 * Emit CloudWatch metrics for recalculation run.
 *
 * @param stats - Statistics from the recalculation
 * @param duration - Total duration in milliseconds
 * @param deps - Metrics and logger dependencies
 */
export function emitRecalcMetrics(
  stats: RecalcStats,
  duration: number,
  deps: { metrics: Metrics; logger: Logger },
): void {
  deps.metrics.addMetric(
    "BucketsProcessed",
    MetricUnit.Count,
    stats.bucketsProcessed,
  );
  deps.metrics.addMetric(
    "BucketsWithDrift",
    MetricUnit.Count,
    stats.bucketsWithDrift,
  );
  deps.metrics.addMetric(
    "TotalDriftMagnitude",
    MetricUnit.Count,
    stats.totalDriftMagnitude,
  );
  deps.metrics.addMetric("ProcessingErrors", MetricUnit.Count, stats.errors);
  deps.metrics.addMetric(
    "PagesProcessed",
    MetricUnit.Count,
    stats.pagesProcessed,
  );
  deps.metrics.addMetric("RecalcDuration", MetricUnit.Milliseconds, duration);
  deps.logger.info("Cardinality recalculation complete", {
    ...stats,
    durationMs: duration,
  });
}
