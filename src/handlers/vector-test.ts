/**
 * @fileoverview Vector Test Lambda Handler.
 *
 * Provides a direct HTTP endpoint for experimenting with Qdrant vector operations.
 * Bypasses SQS queues for immediate feedback during development/testing.
 *
 * Runs in the ms-argus-vector VPC to access the internal Qdrant ALB.
 *
 * Endpoints:
 * - POST /v1/vector/search - Search for similar vectors
 * - POST /v1/vector/upsert - Insert/update vectors
 * - POST /v1/vector/collection - Create a collection
 * - GET  /v1/vector/health - Check Qdrant connectivity
 *
 * @module handlers/vector-test
 */

import {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
  Handler,
} from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { QdrantClient } from "../services/vector/qdrant-client";
import { getVectorWorkerEnv } from "../config/env";

const envConfig = getVectorWorkerEnv();

const logger = new Logger({
  serviceName: envConfig.POWERTOOLS_SERVICE_NAME,
});
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const qdrantClient = new QdrantClient({
  baseUrl: envConfig.QDRANT_URL,
  secretArn: envConfig.QDRANT_SECRET_ARN,
  logger,
});

/**
 * Request body for vector search
 */
interface SearchRequest {
  collection: string;
  vector: number[];
  limit?: number;
  score_threshold?: number;
  filter?: {
    must?: Array<{ key: string; match?: { value: string | number | boolean } }>;
  };
}

/**
 * Request body for vector upsert
 */
interface UpsertRequest {
  collection: string;
  points: Array<{
    id: string | number;
    vector: number[];
    payload?: Record<string, unknown>;
  }>;
}

/**
 * Request body for collection creation
 */
interface CreateCollectionRequest {
  collection: string;
  vector_size: number;
  distance?: "Cosine" | "Euclid" | "Dot";
}

/**
 * HTTP response helper
 */
function jsonResponse(
  statusCode: number,
  body: unknown,
): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
    body: JSON.stringify(body),
  };
}

/**
 * Handle vector search requests
 */
async function handleSearch(
  body: SearchRequest,
): Promise<APIGatewayProxyResultV2> {
  const startTime = Date.now();

  if (!body.collection || !body.vector) {
    return jsonResponse(400, {
      error: "Missing required fields: collection, vector",
    });
  }

  const results = await qdrantClient.search(body.collection, {
    vector: body.vector,
    limit: body.limit ?? 10,
    with_payload: true,
    score_threshold: body.score_threshold,
    filter: body.filter,
  });

  const duration = Date.now() - startTime;
  metrics.addMetric(
    "VectorTestSearchDuration",
    MetricUnit.Milliseconds,
    duration,
  );
  metrics.addMetric(
    "VectorTestSearchResults",
    MetricUnit.Count,
    results.length,
  );

  logger.info("Vector search completed", {
    collection: body.collection,
    vectorDims: body.vector.length,
    resultCount: results.length,
    durationMs: duration,
  });

  return jsonResponse(200, {
    results,
    meta: {
      collection: body.collection,
      query_vector_dims: body.vector.length,
      result_count: results.length,
      duration_ms: duration,
    },
  });
}

/**
 * Handle vector upsert requests
 */
async function handleUpsert(
  body: UpsertRequest,
): Promise<APIGatewayProxyResultV2> {
  const startTime = Date.now();

  if (!body.collection || !body.points || body.points.length === 0) {
    return jsonResponse(400, {
      error: "Missing required fields: collection, points",
    });
  }

  await qdrantClient.upsert(body.collection, { points: body.points });

  const duration = Date.now() - startTime;
  metrics.addMetric(
    "VectorTestUpsertDuration",
    MetricUnit.Milliseconds,
    duration,
  );
  metrics.addMetric(
    "VectorTestUpsertPoints",
    MetricUnit.Count,
    body.points.length,
  );

  logger.info("Vector upsert completed", {
    collection: body.collection,
    pointCount: body.points.length,
    durationMs: duration,
  });

  return jsonResponse(200, {
    success: true,
    meta: {
      collection: body.collection,
      points_upserted: body.points.length,
      duration_ms: duration,
    },
  });
}

/**
 * Handle collection creation requests
 */
async function handleCreateCollection(
  body: CreateCollectionRequest,
): Promise<APIGatewayProxyResultV2> {
  const startTime = Date.now();

  if (!body.collection || !body.vector_size) {
    return jsonResponse(400, {
      error: "Missing required fields: collection, vector_size",
    });
  }

  // Check if collection already exists
  const exists = await qdrantClient.collectionExists(body.collection);
  if (exists) {
    return jsonResponse(409, {
      error: "Collection already exists",
      collection: body.collection,
    });
  }

  await qdrantClient.createCollection(body.collection, {
    vectors: {
      size: body.vector_size,
      distance: body.distance ?? "Cosine",
    },
  });

  const duration = Date.now() - startTime;
  logger.info("Collection created", {
    collection: body.collection,
    vectorSize: body.vector_size,
    distance: body.distance ?? "Cosine",
    durationMs: duration,
  });

  return jsonResponse(201, {
    success: true,
    collection: body.collection,
    vector_size: body.vector_size,
    distance: body.distance ?? "Cosine",
  });
}

/**
 * Handle health check - verify Qdrant connectivity
 */
async function handleHealth(): Promise<APIGatewayProxyResultV2> {
  const startTime = Date.now();

  try {
    // Try to check if a dummy collection exists (will work even if it doesn't)
    await qdrantClient.collectionExists("_health_check");
    const duration = Date.now() - startTime;

    return jsonResponse(200, {
      status: "healthy",
      qdrant_url: envConfig.QDRANT_URL,
      latency_ms: duration,
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error("Health check failed", { error });

    return jsonResponse(503, {
      status: "unhealthy",
      error: error instanceof Error ? error.message : "Unknown error",
      qdrant_url: envConfig.QDRANT_URL,
      latency_ms: duration,
    });
  }
}

/** Parse request body from event */
function parseBody(event: APIGatewayProxyEventV2): unknown {
  if (!event.body) return {};
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString()
    : event.body;
  return JSON.parse(raw);
}

/** Route POST requests to appropriate handler */
async function routePostRequest(
  path: string,
  body: unknown,
): Promise<APIGatewayProxyResultV2 | null> {
  if (path.endsWith("/search")) {
    return handleSearch(body as SearchRequest);
  }
  if (path.endsWith("/upsert")) {
    return handleUpsert(body as UpsertRequest);
  }
  if (path.endsWith("/collection")) {
    return handleCreateCollection(body as CreateCollectionRequest);
  }
  return null;
}

/** Handle routing errors */
function handleError(
  error: unknown,
  path: string,
  method: string,
): APIGatewayProxyResultV2 {
  logger.error("Vector test error", { error, path, method });
  metrics.addMetric("VectorTestError", MetricUnit.Count, 1);
  return jsonResponse(500, {
    error: error instanceof Error ? error.message : "Internal server error",
  });
}

/**
 * Main Lambda handler for vector test endpoint
 */
export const handler: Handler<
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2
> = async (event) => {
  const method = event.requestContext.http.method;
  const path = event.rawPath;

  logger.info("Vector test request", { method, path });

  try {
    if (path.endsWith("/health") && method === "GET") {
      return handleHealth();
    }

    if (method === "POST") {
      const body = parseBody(event);
      const result = await routePostRequest(path, body);
      if (result) return result;
    }

    return jsonResponse(404, {
      error: "Not found",
      availableEndpoints: [
        "GET  /v1/vector/health",
        "POST /v1/vector/search",
        "POST /v1/vector/upsert",
        "POST /v1/vector/collection",
      ],
    });
  } catch (error) {
    if (error instanceof SyntaxError) {
      return jsonResponse(400, { error: "Invalid JSON body" });
    }
    return handleError(error, path, method);
  } finally {
    metrics.publishStoredMetrics();
  }
};
