/**
 * @fileoverview Type definitions for vector worker SQS messages.
 * Defines the message formats for vector search and upsert operations.
 * @module handlers/vector-worker/types
 */

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
