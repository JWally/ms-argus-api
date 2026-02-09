/**
 * @fileoverview Matching Worker Lambda Handler.
 *
 * Consumes fingerprint payloads from SQS and performs multi-tier device matching:
 * - Tier 0: Session cache (already processed)
 * - Tier 0.5: Identity signals (public key, cookies, sigint ID)
 * - Tier 1: Stable hash exact match
 * - Tier 1.5: SimHash fuzzy match (locality-sensitive hashing)
 * - Tier 2: Vector similarity match (if configured) OR compound bucket matching
 *
 * Also supports direct Lambda invocation for admin operations (Valkey cache
 * management), following the same dual-invocation pattern as vector-worker.
 *
 * Results are written to the session cache for retrieval by session-get,
 * and observations are emitted to Firehose for analytics.
 *
 * @module handlers/matching-worker
 */

import { SQSEvent, SQSBatchResponse, Context } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { FirehoseClient } from "@aws-sdk/client-firehose";
import { S3Client } from "@aws-sdk/client-s3";
import { DynamoCacheService } from "../services/cache";

import { getMatchingWorkerEnv } from "../config/env";
import {
  SESSION_TTL_SECONDS,
  MUTATION_GATE_TTL_SECONDS,
} from "../helpers/constants";
import { createMatchingService } from "./matching-worker/config";
import { processRecord } from "./matching-worker/process-record";
import { isAdminRequest } from "./matching-worker/types";
import { handleAdminRequest } from "./matching-worker/admin-handler";
import type { AdminRequest, AdminResponse } from "./matching-worker/types";

const envConfig = getMatchingWorkerEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});
const firehose = new FirehoseClient({});
// Lambda client for vector-worker invocation (Tier 2 vector search)
const lambda = envConfig.VECTOR_WORKER_ARN ? new LambdaClient({}) : undefined;
// S3 client for payload archiving (only created if bucket is configured)
const archiveBucket = envConfig.PAYLOAD_ARCHIVE_BUCKET;
const archiveSampleRate = parseFloat(
  envConfig.PAYLOAD_ARCHIVE_SAMPLE_RATE ?? "0",
);
const s3 = archiveBucket ? new S3Client({}) : null;

const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

/**
 * AWS Lambda handler for the matching worker.
 *
 * Supports two invocation modes:
 *
 * 1. **SQS Event** (async): Triggered by SQS messages from the ingestion queue.
 *    Each message contains a fingerprint payload to be matched against the
 *    device database.
 *
 * 2. **Direct Invocation** (sync): Called directly for admin operations
 *    (Valkey cache management). Request format: `{ action: "flush_cache" | ... }`
 *
 * @param event - SQS event or admin request
 * @param _context - Lambda context
 * @returns SQS batch response or admin response
 *
 * @see {@link processRecord} for individual record processing
 * @see {@link handleAdminRequest} for admin operations
 */
export async function handler(
  event: SQSEvent | AdminRequest,
  _context: Context,
): Promise<SQSBatchResponse | AdminResponse> {
  // Check if this is an admin request (direct Lambda invoke)
  if (isAdminRequest(event)) {
    logger.info("Processing admin request", { action: event.action });
    metrics.addMetric("AdminRequest", MetricUnit.Count, 1);
    return handleAdminRequest(event, { logger, metrics });
  }

  // Otherwise, process as SQS event
  const service = createMatchingService({
    dynamodb,
    sqs,
    lambda,
    cacheService,
    envConfig,
    logger,
    metrics,
  });
  const deps = {
    logger,
    metrics,
    dynamodb,
    firehose,
    envConfig,
    s3,
    archiveBucket,
    archiveSampleRate,
  };
  return processSqsBatch(
    event.Records,
    (record) => processRecord(record, service, deps),
    {
      metrics,
      logger,
      successMetric: "MatchingSuccess",
      errorMetric: "MatchingError",
    },
  );
}
