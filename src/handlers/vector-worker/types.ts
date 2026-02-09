/**
 * @fileoverview Type definitions for vector worker SQS messages.
 * Defines the message formats for vector search and upsert operations.
 * @module handlers/vector-worker/types
 */

import type { QdrantFilter } from "../../services/vector/qdrant-client";

/**
 * Message requesting a vector similarity search in Qdrant.
 *
 * Used for Tier 3 matching to find devices with similar fingerprint vectors.
 *
 * @interface VectorSearchMessage
 */
export interface VectorSearchMessage {
  /** Discriminator for message routing */
  type: "search";
  /** Session requesting the search (for result correlation) */
  session_id: string;
  /** Device ID of the requesting device */
  device_id: string;
  /** Fingerprint embedding vector to search for */
  vector: number[];
  /** Qdrant collection to search in */
  collection: string;
  /** Maximum number of results to return (default: 10) */
  limit?: number;
}

/**
 * Message requesting a vector upsert (insert or update) in Qdrant.
 *
 * Used to store or update a device's fingerprint embedding for future searches.
 *
 * @interface VectorUpsertMessage
 */
export interface VectorUpsertMessage {
  /** Discriminator for message routing */
  type: "upsert";
  /** Device ID (becomes the point ID in Qdrant) */
  device_id: string;
  /** Fingerprint embedding vector to store */
  vector: number[];
  /** Qdrant collection to upsert into */
  collection: string;
  /** Optional metadata payload to store with the vector */
  payload?: Record<string, unknown>;
}

/**
 * Message to keep the Lambda warm without performing operations.
 *
 * Sent periodically by CloudWatch Events or similar to prevent cold starts.
 *
 * @interface WarmupMessage
 */
export interface WarmupMessage {
  /** Flag indicating this is a warmup message */
  warmup: true;
  /** Optional identifier of the warmup source */
  source?: string;
}

/**
 * Union type of all valid vector worker message formats.
 *
 * @typedef {VectorSearchMessage | VectorUpsertMessage | WarmupMessage} VectorMessage
 */
export type VectorMessage =
  | VectorSearchMessage
  | VectorUpsertMessage
  | WarmupMessage;

// ============================================================================
// Synchronous Lambda Invocation Types (for Tier 2 replacement)
// ============================================================================

/**
 * Request for synchronous vector search via Lambda invoke.
 * Used by matching-worker for Tier 2 replacement.
 */
export interface SyncSearchRequest {
  /** Discriminator for invoke type */
  action: "search";
  /** Fingerprint embedding vector to search for */
  vector: number[];
  /** Qdrant collection to search in */
  collection: string;
  /** Maximum number of results to return (default: 10) */
  limit?: number;
  /** Minimum similarity score threshold (default: 0.7) */
  score_threshold?: number;
  /** Whether to auto-create collection if missing */
  auto_create_collection?: boolean;
  /** Optional filter conditions (e.g. mobile screen filter) */
  filter?: QdrantFilter;
}

/**
 * Request for synchronous vector upsert via Lambda invoke.
 * Used by matching-worker to store device vectors.
 */
export interface SyncUpsertRequest {
  /** Discriminator for invoke type */
  action: "upsert";
  /** Device ID (becomes the point ID in Qdrant) */
  device_id: string;
  /** Fingerprint embedding vector to store */
  vector: number[];
  /** Qdrant collection to upsert into */
  collection: string;
  /** Optional metadata payload to store with the vector */
  payload?: Record<string, unknown>;
  /** Whether to auto-create collection if missing */
  auto_create_collection?: boolean;
}

/**
 * Single result from a vector search
 */
export interface VectorMatchResult {
  /** Device ID (point ID in Qdrant) */
  device_id: string;
  /** Similarity score (0-1, higher = more similar) */
  score: number;
  /** Optional payload data */
  payload?: Record<string, unknown>;
}

/**
 * Response from synchronous vector search.
 */
export interface SyncSearchResponse {
  /** Whether the operation succeeded */
  success: true;
  /** Matching results sorted by similarity score */
  results: VectorMatchResult[];
  /** Number of results returned */
  count: number;
  /** Highest similarity score (null if no results) */
  top_score: number | null;
  /** Operation duration in milliseconds */
  duration_ms: number;
}

/**
 * Response from synchronous vector upsert.
 */
export interface SyncUpsertResponse {
  /** Whether the operation succeeded */
  success: true;
  /** Device ID that was upserted */
  device_id: string;
  /** Operation duration in milliseconds */
  duration_ms: number;
}

/**
 * Error response from sync operations.
 */
export interface SyncErrorResponse {
  /** Indicates failure */
  success: false;
  /** Error message */
  error: string;
  /** Error code for categorization */
  code: "COLLECTION_NOT_FOUND" | "QDRANT_ERROR" | "INVALID_REQUEST" | "UNKNOWN";
}

// ============================================================================
// Admin Operations (for data clearing/maintenance)
// ============================================================================

/**
 * Request to list all collections.
 */
export interface SyncListCollectionsRequest {
  action: "list_collections";
}

/**
 * Response with list of collections.
 */
export interface SyncListCollectionsResponse {
  success: true;
  collections: Array<{
    name: string;
    points_count: number;
    vectors_count: number;
  }>;
  duration_ms: number;
}

/**
 * Request to delete a collection.
 */
export interface SyncDeleteCollectionRequest {
  action: "delete_collection";
  collection: string;
}

/**
 * Response from collection deletion.
 */
export interface SyncDeleteCollectionResponse {
  success: true;
  collection: string;
  duration_ms: number;
}

/**
 * Union of all sync invocation request types.
 */
export type SyncInvokeRequest =
  | SyncSearchRequest
  | SyncUpsertRequest
  | SyncListCollectionsRequest
  | SyncDeleteCollectionRequest;

/**
 * Union of all sync invocation response types.
 */
export type SyncInvokeResponse =
  | SyncSearchResponse
  | SyncUpsertResponse
  | SyncListCollectionsResponse
  | SyncDeleteCollectionResponse
  | SyncErrorResponse;
