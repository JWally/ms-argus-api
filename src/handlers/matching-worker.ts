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

// Validate environment variables at module load (cold start)
const envConfig = getMatchingWorkerEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
const dynamodb = new DynamoDBClient({});
const sqs = new SQSClient({});
const firehose = new FirehoseClient({});

// DynamoDB cache service
const cacheService = new DynamoCacheService(dynamodb, {
  tableName: envConfig.SESSION_CACHE_TABLE,
  sessionTtlSeconds: SESSION_TTL_SECONDS,
  mutationGateTtlSeconds: MUTATION_GATE_TTL_SECONDS,
});

/**
 * Matching Worker Lambda Handler
 * Processes fingerprints from SQS and writes results to DynamoDB session cache
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
