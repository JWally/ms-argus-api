/**
 * @fileoverview Vector Worker Lambda Handler.
 *
 * Processes vector operations via Qdrant for similarity matching.
 * Runs in a dedicated VPC (ms-argus-vector) with access to the internal
 * Qdrant ALB endpoint.
 *
 * Supports two invocation modes:
 * 1. **SQS Events**: Async batch processing (original Tier 3 flow)
 * 2. **Direct Invocation**: Sync Lambda-to-Lambda calls (Tier 2 replacement)
 *
 * Operations:
 * - **search**: Find devices with similar fingerprint embeddings
 * - **upsert**: Store/update device fingerprint vectors
 *
 * @module handlers/vector-worker
 */

import { SQSEvent, SQSBatchResponse, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { QdrantClient } from "../services/vector/qdrant-client";
import { getVectorWorkerEnv } from "../config/env";
import { processRecord } from "./vector-worker/process-record";
import {
  handleSyncInvoke,
  isSyncInvokeRequest,
} from "./vector-worker/sync-handler";
import type {
  SyncInvokeRequest,
  SyncInvokeResponse,
} from "./vector-worker/types";

const envConfig = getVectorWorkerEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const _dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});

const qdrantClient = new QdrantClient({
  baseUrl: envConfig.QDRANT_URL,
  secretArn: envConfig.QDRANT_SECRET_ARN,
  logger,
});

/**
 * AWS Lambda handler for the vector worker.
 *
 * Supports two invocation patterns:
 *
 * 1. **SQS Event** (async): Triggered by SQS messages for batch processing.
 *    Results are published to the vector-results queue for persistence.
 *
 * 2. **Direct Invocation** (sync): Called directly by matching-worker via
 *    Lambda invoke. Returns results immediately for Tier 2 replacement.
 *    Request format: `{ action: "search" | "upsert", ... }`
 *
 * @param event - SQS event or sync invoke request
 * @param context - Lambda context
 * @returns SQS batch response or sync invoke response
 *
 * @see {@link processRecord} for SQS message handling
 * @see {@link handleSyncInvoke} for direct invocation handling
 */
export async function handler(
  event: SQSEvent | SyncInvokeRequest,
  _context: Context,
): Promise<SQSBatchResponse | SyncInvokeResponse> {
  // Check if this is a sync invoke (direct Lambda-to-Lambda call)
  if (isSyncInvokeRequest(event)) {
    logger.info("Processing sync invoke request", { action: event.action });
    metrics.addMetric("SyncInvokeRequest", MetricUnit.Count, 1);
    return handleSyncInvoke(event, { qdrantClient, logger, metrics });
  }

  // Otherwise, process as SQS event (original async flow)
  logger.info("Processing SQS batch", { recordCount: event.Records?.length });
  return processSqsBatch(
    event.Records,
    (record) =>
      processRecord(record, {
        qdrantClient,
        sqs,
        vectorResultsQueueUrl: envConfig.VECTOR_RESULTS_QUEUE_URL,
        logger,
        metrics,
      }),
    {
      metrics,
      logger,
      successMetric: "VectorOperationSuccess",
      errorMetric: "VectorOperationError",
    },
  );
}
