// Runs in the ms-argus-vector VPC to access the internal ALB
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
 * Vector Worker Lambda Handler
 * Processes vector operations from SQS and communicates with QDrant
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
