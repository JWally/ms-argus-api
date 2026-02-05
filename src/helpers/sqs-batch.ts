import { SQSBatchResponse, SQSBatchItemFailure, SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

/**
 * Options for SQS batch processing
 */
export interface SqsBatchOptions {
  /** Metrics instance for emitting success/error counts */
  metrics: Metrics;
  /** Logger instance for error logging */
  logger: Logger;
  /** Metric name to emit on successful record processing */
  successMetric: string;
  /** Metric name to emit on failed record processing */
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
 * @param records - Array of SQS records to process
 * @param processRecord - Async function to process each record
 * @param opts - Options including metrics, logger, and metric names
 * @returns SQSBatchResponse with batchItemFailures for partial failure reporting
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
