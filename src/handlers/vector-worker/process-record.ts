/**
 * @fileoverview SQS record processing for the vector worker.
 * Handles vector search and upsert operations via Qdrant.
 * @module handlers/vector-worker/process-record
 */

import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import {
  QdrantClient,
  VectorSearchRequest,
  VectorUpsertRequest,
} from "../../services/vector/qdrant-client";
import { isWarmupMessage } from "../../helpers/is-warmup";
import type {
  VectorMessage,
  VectorSearchMessage,
  VectorUpsertMessage,
} from "./types";

interface ProcessRecordDeps {
  qdrantClient: QdrantClient;
  sqs: SQSClient;
  vectorResultsQueueUrl?: string;
  logger: Logger;
  metrics: Metrics;
}

/**
 * Processes a single SQS record containing a vector operation request.
 *
 * Handles three message types:
 * - **warmup**: Keeps the Lambda warm, no-op
 * - **search**: Queries Qdrant for similar vectors
 * - **upsert**: Inserts or updates a device vector
 *
 * Invalid or unknown message types are logged and skipped without failing.
 *
 * @param record - SQS record containing a VectorMessage
 * @param deps - Service dependencies
 * @param deps.qdrantClient - Qdrant vector database client
 * @param deps.logger - Logger for operation tracking
 * @param deps.metrics - Metrics for CloudWatch
 *
 * @example
 * ```typescript
 * await processRecord(record, { qdrantClient, logger, metrics });
 * ```
 */
export async function processRecord(
  record: SQSRecord,
  deps: ProcessRecordDeps,
): Promise<void> {
  const startTime = Date.now();

  let message: VectorMessage;
  try {
    message = JSON.parse(record.body);
  } catch (parseError) {
    deps.logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200),
    });
    deps.metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return;
  }

  if (isWarmupMessage(record.body)) {
    deps.logger.info("Warmup ping received - keeping pipeline warm");
    deps.metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return;
  }

  if (!("type" in message)) {
    deps.logger.warn("Unknown message format", { message });
    deps.metrics.addMetric("UnknownMessageType", MetricUnit.Count, 1);
    return;
  }

  if (message.type === "search") {
    await handleSearch(message, deps);
  } else if (message.type === "upsert") {
    await handleUpsert(message, deps);
  } else {
    deps.logger.warn("Unknown message type", { message });
    deps.metrics.addMetric("UnknownMessageType", MetricUnit.Count, 1);
  }

  const duration = Date.now() - startTime;
  deps.metrics.addMetric(
    "VectorOperationDuration",
    MetricUnit.Milliseconds,
    duration,
  );
}

/**
 * Handles a vector search request.
 *
 * Queries Qdrant for vectors similar to the provided vector, then publishes
 * results to the vector-results SQS queue for persistence to DynamoDB.
 *
 * @param message - Search request with vector and parameters
 * @param deps - Service dependencies
 *
 * @internal
 */
async function handleSearch(
  message: VectorSearchMessage,
  deps: ProcessRecordDeps,
): Promise<void> {
  deps.logger.info("Processing vector search", {
    session_id: message.session_id,
    collection: message.collection,
    limit: message.limit,
  });

  const request: VectorSearchRequest = {
    vector: message.vector,
    limit: message.limit ?? 10,
    with_payload: true,
  };

  const results = await deps.qdrantClient.search(message.collection, request);

  deps.metrics.addMetric("VectorSearchComplete", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "VectorSearchResultCount",
    MetricUnit.Count,
    results.length,
  );

  deps.logger.info("Vector search complete", {
    session_id: message.session_id,
    result_count: results.length,
    top_score: results[0]?.score,
  });

  // Publish results to vector-results queue for persistence
  if (deps.vectorResultsQueueUrl && message.session_id) {
    await deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: deps.vectorResultsQueueUrl,
        MessageBody: JSON.stringify({
          session_id: message.session_id,
          results: results.map((r) => ({
            id: r.id,
            score: r.score,
            payload: r.payload,
          })),
          collection: message.collection,
          timestamp: Date.now(),
        }),
      }),
    );

    deps.metrics.addMetric("VectorResultsPublished", MetricUnit.Count, 1);
    deps.logger.info("Vector results published to queue", {
      session_id: message.session_id,
      result_count: results.length,
    });
  }
}

/**
 * Handles a vector upsert request.
 *
 * Inserts or updates a device's vector representation in Qdrant.
 * Used for future vector-based similarity matching (Tier 3).
 *
 * @param message - Upsert request with device ID, vector, and optional payload
 * @param deps - Service dependencies
 *
 * @internal
 */
async function handleUpsert(
  message: VectorUpsertMessage,
  deps: ProcessRecordDeps,
): Promise<void> {
  deps.logger.info("Processing vector upsert", {
    device_id: message.device_id,
    collection: message.collection,
  });

  const request: VectorUpsertRequest = {
    points: [
      {
        id: message.device_id,
        vector: message.vector,
        payload: message.payload,
      },
    ],
  };

  await deps.qdrantClient.upsert(message.collection, request);

  deps.metrics.addMetric("VectorUpsertComplete", MetricUnit.Count, 1);

  deps.logger.info("Vector upsert complete", {
    device_id: message.device_id,
    collection: message.collection,
  });
}
