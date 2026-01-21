// src/handlers/vector-worker.ts
// Vector search worker Lambda for QDrant integration
// Runs in the ms-argus-vector VPC to access the internal ALB
import {
  SQSHandler,
  SQSBatchResponse,
  SQSBatchItemFailure,
  SQSRecord,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  QdrantClient,
  VectorSearchRequest,
  VectorUpsertRequest,
} from "../services/vector/qdrant-client";
import { getVectorWorkerEnv, VectorWorkerEnvConfig } from "../config/env";

// Validate environment variables at module load (cold start)
// Throws immediately if required env vars are missing
const envConfig: VectorWorkerEnvConfig = getVectorWorkerEnv();

// Powertools (using validated config)
const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

// AWS SDK clients (reused across invocations)
// DynamoDB client for future profile lookups
const _dynamodb = new DynamoDBClient({});

// QDrant client (reused across invocations)
const qdrantClient = new QdrantClient({
  baseUrl: envConfig.QDRANT_URL,
  secretArn: envConfig.QDRANT_SECRET_ARN,
  logger,
});

/**
 * Message types for the vector worker
 */
interface VectorSearchMessage {
  type: "search";
  session_id: string;
  device_id: string;
  vector: number[];
  collection: string;
  limit?: number;
}

interface VectorUpsertMessage {
  type: "upsert";
  device_id: string;
  vector: number[];
  collection: string;
  payload?: Record<string, unknown>;
}

interface WarmupMessage {
  warmup: true;
  source?: string;
}

type VectorMessage = VectorSearchMessage | VectorUpsertMessage | WarmupMessage;

/**
 * Vector Worker Lambda Handler
 * Processes vector operations from SQS and communicates with QDrant
 */
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];

  for (const record of event.Records) {
    try {
      await processRecord(record);
      metrics.addMetric("VectorOperationSuccess", MetricUnit.Count, 1);
    } catch (error) {
      logger.error("Failed to process vector record", {
        error,
        messageId: record.messageId,
      });
      metrics.addMetric("VectorOperationError", MetricUnit.Count, 1);
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }

  metrics.publishStoredMetrics();
  return { batchItemFailures };
};

/**
 * Check if this is a warmup message from EventBridge
 */
function isWarmupMessage(message: VectorMessage): message is WarmupMessage {
  return "warmup" in message && message.warmup === true;
}

/**
 * Process a single SQS record
 */
async function processRecord(record: SQSRecord): Promise<void> {
  const startTime = Date.now();

  // Parse message
  let message: VectorMessage;
  try {
    message = JSON.parse(record.body);
  } catch (parseError) {
    logger.error("Malformed JSON payload - skipping message", {
      error: parseError,
      messageId: record.messageId,
      bodyPreview: record.body.slice(0, 200),
    });
    metrics.addMetric("MalformedPayload", MetricUnit.Count, 1);
    return; // Don't retry - mark as processed
  }

  // Handle warmup messages
  if (isWarmupMessage(message)) {
    logger.info("Warmup ping received - keeping pipeline warm");
    metrics.addMetric("WarmupPing", MetricUnit.Count, 1);
    return;
  }

  // Route to appropriate handler
  if (message.type === "search") {
    await handleSearch(message);
  } else if (message.type === "upsert") {
    await handleUpsert(message);
  } else {
    logger.warn("Unknown message type", { message });
    metrics.addMetric("UnknownMessageType", MetricUnit.Count, 1);
  }

  const duration = Date.now() - startTime;
  metrics.addMetric(
    "VectorOperationDuration",
    MetricUnit.Milliseconds,
    duration,
  );
}

/**
 * Handle vector search request
 */
async function handleSearch(message: VectorSearchMessage): Promise<void> {
  logger.info("Processing vector search", {
    session_id: message.session_id,
    collection: message.collection,
    limit: message.limit,
  });

  const request: VectorSearchRequest = {
    vector: message.vector,
    limit: message.limit ?? 10,
    with_payload: true,
  };

  const results = await qdrantClient.search(message.collection, request);

  metrics.addMetric("VectorSearchComplete", MetricUnit.Count, 1);
  metrics.addMetric(
    "VectorSearchResultCount",
    MetricUnit.Count,
    results.length,
  );

  logger.info("Vector search complete", {
    session_id: message.session_id,
    result_count: results.length,
    top_score: results[0]?.score,
  });

  // TODO: Write results to session cache or callback queue
  // This depends on how the matching service wants to consume vector results
}

/**
 * Handle vector upsert request
 */
async function handleUpsert(message: VectorUpsertMessage): Promise<void> {
  logger.info("Processing vector upsert", {
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

  await qdrantClient.upsert(message.collection, request);

  metrics.addMetric("VectorUpsertComplete", MetricUnit.Count, 1);

  logger.info("Vector upsert complete", {
    device_id: message.device_id,
    collection: message.collection,
  });
}
