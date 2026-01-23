// src/helpers/sqs-batch.ts
// Shared SQS batch processing pattern for all worker handlers

import { SQSBatchResponse, SQSBatchItemFailure, SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

export interface SqsBatchOptions {
  metrics: Metrics;
  logger: Logger;
  successMetric: string;
  errorMetric: string;
}

/**
 * Process an SQS batch with consistent error handling, metrics, and partial failure reporting.
 *
 * Enforces the standard pattern:
 * 1. Iterate over records
 * 2. On success: emit success metric
 * 3. On error: log error, emit error metric, report partial failure
 * 4. Publish stored metrics
 * 5. Return batchItemFailures for SQS partial batch failure
 */
export async function processSqsBatch(
  records: SQSRecord[],
  processRecord: (record: SQSRecord) => Promise<void>,
  opts: SqsBatchOptions,
): Promise<SQSBatchResponse> {
  const batchItemFailures: SQSBatchItemFailure[] = [];

  for (const record of records) {
    try {
      await processRecord(record);
      opts.metrics.addMetric(opts.successMetric, MetricUnit.Count, 1);
    } catch (error) {
      opts.logger.error("Failed to process record", {
        error,
        messageId: record.messageId,
      });
      opts.metrics.addMetric(opts.errorMetric, MetricUnit.Count, 1);
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }

  opts.metrics.publishStoredMetrics();
  return { batchItemFailures };
}
