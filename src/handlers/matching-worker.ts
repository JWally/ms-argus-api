/**
 * @fileoverview Matching Worker Lambda Handler.
 *
 * Consumes fingerprint payloads from SQS and performs multi-tier device matching:
 * - Tier 0: Session cache (already processed)
 * - Tier 0.5: Identity signals (public key, cookies, sigint ID)
 * - Tier 1: Stable hash exact match
 * - Tier 1.5: SimHash fuzzy match (locality-sensitive hashing)
 * - Tier 2: Compound bucket matching (UA + IP + scoring)
 *
 * Results are written to the session cache for retrieval by session-get,
 * and observations are emitted to Firehose for analytics.
 *
 * @module handlers/matching-worker
 */

import { SQSHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { processSqsBatch } from "../helpers/sqs-batch";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { FirehoseClient } from "@aws-sdk/client-firehose";
import { DynamoCacheService } from "../services/cache";
import { getMatchingWorkerEnv } from "../config/env";
import {
  SESSION_TTL_SECONDS,
  MUTATION_GATE_TTL_SECONDS,
} from "../helpers/constants";
import { createMatchingService } from "./matching-worker/config";
import { processRecord } from "./matching-worker/process-record";

const envConfig = getMatchingWorkerEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});
const firehose = new FirehoseClient({});

const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

/**
 * AWS Lambda handler for the matching worker.
 *
 * Triggered by SQS messages from the ingestion queue. Each message contains
 * a fingerprint payload to be matched against the device database.
 *
 * Processing flow:
 * 1. Parse and validate SQS record
 * 2. Run multi-tier matching algorithm
 * 3. Write result to session cache
 * 4. Emit observation to Firehose (optional)
 * 5. Queue profile update message
 *
 * Uses partial batch failure reporting - failed records are retried,
 * successful records are not reprocessed.
 *
 * @param event - SQS event containing fingerprint records
 * @returns SQS batch response with partial failures
 *
 * @see {@link processRecord} for individual record processing
 * @see {@link MatchingService} for matching algorithm details
 */
export const handler: SQSHandler = async (event) => {
  const service = createMatchingService({
    dynamodb,
    sqs,
    cacheService,
    envConfig,
  });
  const deps = { logger, metrics, dynamodb, firehose, envConfig };
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
};
