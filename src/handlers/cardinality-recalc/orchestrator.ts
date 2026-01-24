import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { scanBucketKeysPages } from "./dynamo-ops";
import { processBucket } from "./bucket-processor";

export interface RecalcStats {
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
