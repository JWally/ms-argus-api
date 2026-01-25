/**
 * @fileoverview Vector Worker Lambda Handler.
 *
 * Processes vector operations via Qdrant for Tier 3 similarity matching.
 * Runs in a dedicated VPC (ms-argus-vector) with access to the internal
 * Qdrant ALB endpoint.
 *
 * Operations:
 * - **search**: Find devices with similar fingerprint embeddings
 * - **upsert**: Store/update device fingerprint vectors
 *
 * This enables future ML-based matching for devices where traditional
 * fingerprinting is insufficient (e.g., heavily randomized browsers).
 *
 * @module handlers/vector-worker
 */

import { SQSHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { QdrantClient } from "../services/vector/qdrant-client";
import { getVectorWorkerEnv } from "../config/env";
import { processRecord } from "./vector-worker/process-record";

const envConfig = getVectorWorkerEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const _dynamodb = new DynamoDBClient({});

const qdrantClient = new QdrantClient({
  baseUrl: envConfig.QDRANT_URL,
  secretArn: envConfig.QDRANT_SECRET_ARN,
  logger,
});

/**
 * AWS Lambda handler for the vector worker.
 *
 * Triggered by SQS messages requesting vector operations. The worker
 * communicates with Qdrant via HTTP through a VPC-internal ALB.
 *
 * Message types:
 * - `search`: Query for similar vectors, return matches
 * - `upsert`: Insert or update a device's vector
 * - `warmup`: Keep-alive message, no operation
 *
 * Uses partial batch failure reporting for reliable processing.
 *
 * @param event - SQS event containing vector operation records
 * @returns SQS batch response with partial failures
 *
 * @see {@link processRecord} for message handling logic
 * @see {@link QdrantClient} for vector database operations
 */
export const handler: SQSHandler = async (event) => {
  return processSqsBatch(
    event.Records,
    (record) => processRecord(record, { qdrantClient, logger, metrics }),
    {
      metrics,
      logger,
      successMetric: "VectorOperationSuccess",
      errorMetric: "VectorOperationError",
    },
  );
};
