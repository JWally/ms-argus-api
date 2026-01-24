import { SQSRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
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

export async function processRecord(
  record: SQSRecord,
  deps: { qdrantClient: QdrantClient; logger: Logger; metrics: Metrics },
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

async function handleSearch(
  message: VectorSearchMessage,
  deps: { qdrantClient: QdrantClient; logger: Logger; metrics: Metrics },
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

  // TODO: Write results to session cache or callback queue
}

async function handleUpsert(
  message: VectorUpsertMessage,
  deps: { qdrantClient: QdrantClient; logger: Logger; metrics: Metrics },
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
