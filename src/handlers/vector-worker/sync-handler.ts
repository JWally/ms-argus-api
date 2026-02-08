/**
 * @fileoverview Synchronous Lambda invocation handler for vector operations.
 * Enables direct Lambda-to-Lambda calls for Tier 2 matching replacement.
 * @module handlers/vector-worker/sync-handler
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { createHash } from "crypto";
import {
  QdrantClient,
  VectorSearchRequest,
  QdrantError,
} from "../../services/vector/qdrant-client";
import type {
  SyncInvokeRequest,
  SyncInvokeResponse,
  SyncSearchRequest,
  SyncUpsertRequest,
  SyncListCollectionsRequest,
  SyncDeleteCollectionRequest,
  VectorMatchResult,
} from "./types";

/** Vector dimensions for fingerprint embeddings */
const VECTOR_DIMENSIONS = 256;

/**
 * Convert a device ID to a valid Qdrant point ID (UUID format).
 */
function deviceIdToPointId(deviceId: string): string {
  const hash = createHash("md5").update(deviceId).digest("hex");
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
}

/**
 * Convert a Qdrant point ID back to device ID via payload.
 */
function pointIdToDeviceId(
  pointId: string | number,
  payload?: Record<string, unknown>,
): string {
  if (payload?.device_id && typeof payload.device_id === "string") {
    return payload.device_id;
  }
  return String(pointId);
}

interface SyncHandlerDeps {
  qdrantClient: QdrantClient;
  logger: Logger;
  metrics: Metrics;
}

/** Error codes for sync responses */
type ErrorCode =
  | "COLLECTION_NOT_FOUND"
  | "QDRANT_ERROR"
  | "INVALID_REQUEST"
  | "UNKNOWN";

/** Create an error response */
function errorResponse(
  error: string,
  code: ErrorCode,
): { success: false; error: string; code: ErrorCode } {
  return { success: false, error, code };
}

/** Handle Qdrant errors with appropriate codes */
function handleQdrantError(
  error: QdrantError,
  collection: string,
): { success: false; error: string; code: ErrorCode } {
  const isNotFound =
    error.statusCode === 404 ||
    error.message.includes("not found") ||
    error.message.includes("doesn't exist");

  if (isNotFound) {
    return errorResponse(
      `Collection '${collection}' not found`,
      "COLLECTION_NOT_FOUND",
    );
  }
  return errorResponse(error.message, "QDRANT_ERROR");
}

/** Validate vector array */
function validateVector(
  vector: unknown,
): { valid: true } | { valid: false; error: string } {
  if (!Array.isArray(vector) || vector.length !== VECTOR_DIMENSIONS) {
    const len = Array.isArray(vector) ? vector.length : 0;
    return {
      valid: false,
      error: `Vector must be array of ${VECTOR_DIMENSIONS} numbers, got ${len}`,
    };
  }
  return { valid: true };
}

/** Dispatch table for action handlers. */
const ACTION_HANDLERS: Record<
  string,
  (
    request: SyncInvokeRequest,
    startTime: number,
    deps: SyncHandlerDeps,
  ) => Promise<SyncInvokeResponse>
> = {
  search: (r, t, d) => handleSyncSearch(r as SyncSearchRequest, t, d),
  upsert: (r, t, d) => handleSyncUpsert(r as SyncUpsertRequest, t, d),
  list_collections: (r, t, d) =>
    handleListCollections(r as SyncListCollectionsRequest, t, d),
  delete_collection: (r, t, d) =>
    handleDeleteCollection(r as SyncDeleteCollectionRequest, t, d),
};

/** Convert a caught error into a SyncInvokeResponse. */
function handleInvokeError(
  error: unknown,
  request: SyncInvokeRequest,
  deps: SyncHandlerDeps,
): SyncInvokeResponse {
  deps.logger.error("Sync invoke failed", { error, request });
  deps.metrics.addMetric("SyncInvokeError", MetricUnit.Count, 1);

  if (error instanceof QdrantError) {
    const collection =
      "collection" in request ? (request.collection as string) : "unknown";
    return handleQdrantError(error, collection);
  }
  return errorResponse(
    error instanceof Error ? error.message : "Unknown error",
    "UNKNOWN",
  );
}

const AUTO_CREATE_ACTIONS = new Set(["search", "upsert"]);

/**
 * Handle a synchronous Lambda invocation for vector operations.
 */
export async function handleSyncInvoke(
  request: SyncInvokeRequest,
  deps: SyncHandlerDeps,
): Promise<SyncInvokeResponse> {
  const startTime = Date.now();

  try {
    if (!request || !("action" in request)) {
      return errorResponse(
        "Missing action field in request",
        "INVALID_REQUEST",
      );
    }

    if (
      "auto_create_collection" in request &&
      request.auto_create_collection &&
      "collection" in request &&
      AUTO_CREATE_ACTIONS.has(request.action)
    ) {
      await ensureCollectionExists(request.collection, deps);
    }

    const handler = ACTION_HANDLERS[request.action];
    if (!handler) {
      return errorResponse(
        `Unknown action: ${request.action}`,
        "INVALID_REQUEST",
      );
    }
    return await handler(request, startTime, deps);
  } catch (error) {
    return handleInvokeError(error, request, deps);
  }
}

/** Log and emit metrics for search completion */
function recordSearchMetrics(
  deps: SyncHandlerDeps,
  collection: string,
  results: VectorMatchResult[],
  duration: number,
): void {
  deps.metrics.addMetric("SyncSearchComplete", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "SyncSearchDuration",
    MetricUnit.Milliseconds,
    duration,
  );
  deps.metrics.addMetric(
    "SyncSearchResultCount",
    MetricUnit.Count,
    results.length,
  );

  deps.logger.info("Sync vector search complete", {
    collection,
    result_count: results.length,
    top_score: results[0]?.score ?? null,
    duration_ms: duration,
  });
}

/**
 * Handle synchronous vector search request.
 */
async function handleSyncSearch(
  request: SyncSearchRequest,
  startTime: number,
  deps: SyncHandlerDeps,
): Promise<SyncInvokeResponse> {
  const validation = validateVector(request.vector);
  if (!validation.valid) {
    return errorResponse(validation.error, "INVALID_REQUEST");
  }

  deps.logger.info("Processing sync vector search", {
    collection: request.collection,
    limit: request.limit,
    score_threshold: request.score_threshold,
  });

  const searchRequest: VectorSearchRequest = {
    vector: request.vector,
    limit: request.limit ?? 10,
    with_payload: true,
    score_threshold: request.score_threshold ?? 0.7,
  };

  const results = await deps.qdrantClient.search(
    request.collection,
    searchRequest,
  );

  const matchResults: VectorMatchResult[] = results.map((r) => ({
    device_id: pointIdToDeviceId(r.id, r.payload),
    score: r.score,
    payload: r.payload,
  }));

  const duration = Date.now() - startTime;
  recordSearchMetrics(deps, request.collection, matchResults, duration);

  return {
    success: true,
    results: matchResults,
    count: matchResults.length,
    top_score: matchResults[0]?.score ?? null,
    duration_ms: duration,
  };
}

/** Log and emit metrics for upsert completion */
function recordUpsertMetrics(
  deps: SyncHandlerDeps,
  deviceId: string,
  collection: string,
  duration: number,
): void {
  deps.metrics.addMetric("SyncUpsertComplete", MetricUnit.Count, 1);
  deps.metrics.addMetric(
    "SyncUpsertDuration",
    MetricUnit.Milliseconds,
    duration,
  );

  deps.logger.info("Sync vector upsert complete", {
    device_id: deviceId,
    collection,
    duration_ms: duration,
  });
}

/**
 * Handle synchronous vector upsert request.
 */
async function handleSyncUpsert(
  request: SyncUpsertRequest,
  startTime: number,
  deps: SyncHandlerDeps,
): Promise<SyncInvokeResponse> {
  const validation = validateVector(request.vector);
  if (!validation.valid) {
    return errorResponse(validation.error, "INVALID_REQUEST");
  }

  if (!request.device_id) {
    return errorResponse("Missing device_id", "INVALID_REQUEST");
  }

  const pointId = deviceIdToPointId(request.device_id);

  deps.logger.info("Processing sync vector upsert", {
    device_id: request.device_id,
    point_id: pointId,
    collection: request.collection,
  });

  await deps.qdrantClient.upsert(request.collection, {
    points: [
      {
        id: pointId,
        vector: request.vector,
        payload: { ...request.payload, device_id: request.device_id },
      },
    ],
  });

  const duration = Date.now() - startTime;
  recordUpsertMetrics(deps, request.device_id, request.collection, duration);

  return {
    success: true,
    device_id: request.device_id,
    duration_ms: duration,
  };
}

/**
 * Ensure a collection exists, creating it if necessary.
 */
async function ensureCollectionExists(
  collection: string,
  deps: SyncHandlerDeps,
): Promise<void> {
  const exists = await deps.qdrantClient.collectionExists(collection);
  if (!exists) {
    deps.logger.info("Auto-creating collection", { collection });
    try {
      await deps.qdrantClient.createCollection(collection, {
        vectors: { size: VECTOR_DIMENSIONS, distance: "Cosine" },
      });
      deps.metrics.addMetric("CollectionAutoCreated", MetricUnit.Count, 1);
      deps.logger.info("Collection created", { collection });
    } catch (error) {
      if (
        error instanceof Error &&
        (error.message.includes("already exists") ||
          error.message.includes("Conflict"))
      ) {
        deps.logger.info("Collection already exists (race condition)", {
          collection,
        });
        return;
      }
      throw error;
    }
  }
}

/**
 * Handle list collections request (admin operation).
 */
async function handleListCollections(
  _request: SyncListCollectionsRequest,
  startTime: number,
  deps: SyncHandlerDeps,
): Promise<SyncInvokeResponse> {
  deps.logger.info("Listing all collections");

  const collectionNames = await deps.qdrantClient.listCollections();
  const collections = [];

  for (const name of collectionNames) {
    try {
      const info = await deps.qdrantClient.getCollectionInfo(name);
      collections.push({
        name,
        points_count: info.points_count,
        vectors_count: info.vectors_count,
      });
    } catch {
      collections.push({ name, points_count: 0, vectors_count: 0 });
    }
  }

  const duration = Date.now() - startTime;
  deps.metrics.addMetric("ListCollectionsComplete", MetricUnit.Count, 1);

  deps.logger.info("Listed collections", {
    count: collections.length,
    duration_ms: duration,
  });

  return {
    success: true,
    collections,
    duration_ms: duration,
  };
}

/**
 * Handle delete collection request (admin operation).
 */
async function handleDeleteCollection(
  request: SyncDeleteCollectionRequest,
  startTime: number,
  deps: SyncHandlerDeps,
): Promise<SyncInvokeResponse> {
  deps.logger.info("Deleting collection", { collection: request.collection });

  await deps.qdrantClient.deleteCollection(request.collection);

  const duration = Date.now() - startTime;
  deps.metrics.addMetric("DeleteCollectionComplete", MetricUnit.Count, 1);

  deps.logger.info("Collection deleted", {
    collection: request.collection,
    duration_ms: duration,
  });

  return {
    success: true,
    collection: request.collection,
    duration_ms: duration,
  };
}

/**
 * Check if an event is a sync invoke request (vs SQS event).
 */
export function isSyncInvokeRequest(
  event: unknown,
): event is SyncInvokeRequest {
  return (
    typeof event === "object" &&
    event !== null &&
    "action" in event &&
    (event as { action: string }).action !== undefined
  );
}
