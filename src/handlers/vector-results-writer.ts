/**
 * @fileoverview Vector Results Writer Lambda Handler.
 *
 * Consumes vector search results from SQS and writes them to DynamoDB
 * for retrieval by the session-get endpoint.
 *
 * @module handlers/vector-results-writer
 */

import { SQSHandler, SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { processSqsBatch } from "../helpers/sqs-batch";
import { getVectorResultsWriterEnv } from "../config/env";
import { isWarmupMessage } from "../helpers/is-warmup";

/** TTL for vector results in seconds (5 minutes) */
const VECTOR_RESULTS_TTL_SECONDS = 300;

const envConfig = getVectorResultsWriterEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});

/** Message format received from the vector worker */
interface VectorResultsMessage {
  session_id: string;
  results: VectorSearchResult[];
  collection: string;
  timestamp: number;
}

/** Individual vector search result */
interface VectorSearchResult {
  id: string;
  score: number;
  payload?: Record<string, unknown>;
}

/** Parse and validate a VectorResultsMessage from JSON */
function parseMessage(
  record: SQSRecord,
): { valid: true; message: VectorResultsMessage } | { valid: false } {
  let message: VectorResultsMessage;
  try {
    message = JSON.parse(record.body);
  } catch (parseError) {
    logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200),
    });
    metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return { valid: false };
  }

  if (!message.session_id) {
    logger.warn("Missing session_id in message - skipping", {
      messageId: record.messageId,
    });
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    return { valid: false };
  }

  return { valid: true, message };
}

/** Write vector results to DynamoDB */
async function writeResultsToDynamo(
  message: VectorResultsMessage,
): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + VECTOR_RESULTS_TTL_SECONDS;

  await dynamodb.send(
    new PutItemCommand({
      TableName: envConfig.VECTOR_RESULTS_TABLE,
      Item: marshall({
        session_id: message.session_id,
        results: message.results,
        collection: message.collection,
        result_count: message.results.length,
        top_score: message.results[0]?.score ?? null,
        created_at: message.timestamp,
        ttl,
      }),
    }),
  );
}

/**
 * Processes a single SQS record containing vector search results.
 */
async function processRecord(record: SQSRecord): Promise<void> {
  if (isWarmupMessage(record.body)) {
    logger.info("Warmup ping received");
    metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return;
  }

  const parsed = parseMessage(record);
  if (!parsed.valid) return;

  await writeResultsToDynamo(parsed.message);

  logger.info("Vector results written", {
    session_id: parsed.message.session_id,
    result_count: parsed.message.results.length,
    collection: parsed.message.collection,
  });

  metrics.addMetric("VectorResultsWritten", MetricUnit.Count, 1);
  metrics.addMetric(
    "VectorResultCount",
    MetricUnit.Count,
    parsed.message.results.length,
  );
}

/**
 * AWS Lambda handler for the vector results writer.
 */
export const handler: SQSHandler = async (event) => {
  return processSqsBatch(event.Records, processRecord, {
    metrics,
    logger,
    successMetric: "VectorResultsWriteSuccess",
    errorMetric: "VectorResultsWriteError",
  });
};
