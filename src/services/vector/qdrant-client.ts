// Thin wrapper around @qdrant/js-client-rest with AWS Secrets Manager auth
import { QdrantClient as OfficialClient } from "@qdrant/js-client-rest";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import type { Logger } from "@aws-lambda-powertools/logger";

/**
 * Configuration for QdrantClient
 */
export interface QdrantClientConfig {
  /** Base URL of the Qdrant server */
  baseUrl: string;
  /** ARN of the AWS Secrets Manager secret containing the API key */
  secretArn: string;
  /** Logger instance for debugging */
  logger: Logger;
  /** Request timeout in milliseconds (default 10000) */
  timeoutMs?: number;
  /** Optional pre-configured Secrets Manager client */
  secretsClient?: SecretsManagerClient;
}

/**
 * Request parameters for vector similarity search
 */
export interface VectorSearchRequest {
  /** Query vector for similarity search */
  vector: number[];
  /** Maximum number of results to return */
  limit: number;
  /** Include payload data in results */
  with_payload?: boolean;
  /** Include vector data in results */
  with_vector?: boolean;
  /** Minimum similarity score threshold */
  score_threshold?: number;
  /** Filter conditions to apply */
  filter?: QdrantFilter;
}

/**
 * Filter conditions for Qdrant queries
 */
export interface QdrantFilter {
  /** All conditions must match (AND) */
  must?: QdrantCondition[];
  /** At least one condition should match (OR) */
  should?: QdrantCondition[];
  /** None of these conditions should match */
  must_not?: QdrantCondition[];
}

/**
 * Single filter condition for a Qdrant query
 */
export interface QdrantCondition {
  /** Payload field key to filter on */
  key: string;
  /** Exact match condition */
  match?: { value: string | number | boolean };
  /** Range condition for numeric fields */
  range?: { gt?: number; gte?: number; lt?: number; lte?: number };
}

/**
 * Single result from a vector search
 */
export interface VectorSearchResult {
  /** Point ID (string ULID or numeric ID) */
  id: string | number;
  /** Similarity score (higher = more similar) */
  score: number;
  /** Optional payload data attached to the point */
  payload?: Record<string, unknown>;
  /** Optional vector data (if requested) */
  vector?: number[];
}

/**
 * Request to upsert (insert or update) vectors
 */
export interface VectorUpsertRequest {
  /** Array of points to upsert */
  points: VectorPoint[];
}

/**
 * Single vector point for storage
 */
export interface VectorPoint {
  /** Unique identifier for the point */
  id: string | number;
  /** Vector embedding */
  vector: number[];
  /** Optional metadata payload */
  payload?: Record<string, unknown>;
}

/**
 * Thin wrapper around @qdrant/js-client-rest with AWS Secrets Manager auth
 * Handles API key caching and automatic client recreation on key rotation
 */
export class QdrantClient {
  private readonly secretsClient: SecretsManagerClient;
  private readonly config: QdrantClientConfig;
  private client: OfficialClient | null = null;
  private cachedApiKey: string | null = null;
  private apiKeyExpiresAt = 0;
  private static readonly API_KEY_CACHE_TTL_MS = 15 * 60 * 1000;

  /**
   * Create a new QdrantClient
   * @param config - Client configuration including URL and secret ARN
   */
  constructor(config: QdrantClientConfig) {
    this.config = config;
    this.secretsClient = config.secretsClient ?? new SecretsManagerClient({});
  }

  /**
   * Search for similar vectors in a collection
   * @param collection - Name of the collection to search
   * @param request - Search parameters including query vector and filters
   * @returns Array of matching results sorted by similarity
   */
  async search(
    collection: string,
    request: VectorSearchRequest,
  ): Promise<VectorSearchResult[]> {
    const client = await this.getClient();
    const results = await client.search(collection, {
      vector: request.vector,
      limit: request.limit,
      with_payload: request.with_payload,
      with_vector: request.with_vector,
      score_threshold: request.score_threshold,
      filter: request.filter,
    });
    return results as VectorSearchResult[];
  }

  /**
   * Insert or update vectors in a collection
   * @param collection - Name of the collection
   * @param request - Points to upsert
   */
  async upsert(
    collection: string,
    request: VectorUpsertRequest,
  ): Promise<void> {
    const client = await this.getClient();
    await client.upsert(collection, { points: request.points });
  }

  /**
   * Delete vectors from a collection by ID
   * @param collection - Name of the collection
   * @param ids - Array of point IDs to delete
   */
  async delete(collection: string, ids: (string | number)[]): Promise<void> {
    const client = await this.getClient();
    await client.delete(collection, { points: ids });
  }

  /**
   * Retrieve vectors by ID from a collection
   * @param collection - Name of the collection
   * @param ids - Array of point IDs to retrieve
   * @param options - Options for including payload and vector data
   * @returns Array of retrieved points
   */
  async get(
    collection: string,
    ids: (string | number)[],
    options?: { with_payload?: boolean; with_vector?: boolean },
  ): Promise<VectorSearchResult[]> {
    const client = await this.getClient();
    const results = await client.retrieve(collection, {
      ids,
      with_payload: options?.with_payload ?? true,
      with_vector: options?.with_vector ?? false,
    });
    return results as VectorSearchResult[];
  }

  /**
   * Check if a collection exists
   * @param collection - Name of the collection to check
   * @returns True if collection exists
   */
  async collectionExists(collection: string): Promise<boolean> {
    const client = await this.getClient();
    const result = await client.collectionExists(collection);
    return result.exists;
  }

  /**
   * Create a new collection
   * @param collection - Name for the new collection
   * @param options - Collection configuration including vector size and distance metric
   */
  async createCollection(
    collection: string,
    options: {
      vectors: { size: number; distance: "Cosine" | "Euclid" | "Dot" };
    },
  ): Promise<void> {
    const client = await this.getClient();
    await client.createCollection(collection, options);
  }

  /**
   * Get or create the Qdrant client instance
   * @returns Configured Qdrant client
   */
  private async getClient(): Promise<OfficialClient> {
    const apiKey = await this.getApiKey();
    if (!this.client) {
      this.client = new OfficialClient({
        url: this.config.baseUrl,
        apiKey,
        timeout: this.config.timeoutMs ?? 10000,
      });
    }
    return this.client;
  }

  /**
   * Get the API key from cache or fetch from Secrets Manager
   * @returns API key string
   */
  private async getApiKey(): Promise<string> {
    const now = Date.now();
    if (this.cachedApiKey && now < this.apiKeyExpiresAt) {
      return this.cachedApiKey;
    }

    const response = await this.secretsClient.send(
      new GetSecretValueCommand({ SecretId: this.config.secretArn }),
    );
    if (!response.SecretString) {
      throw new QdrantError("QDrant API key secret is empty", 0, "");
    }

    this.cachedApiKey = response.SecretString;
    this.apiKeyExpiresAt = now + QdrantClient.API_KEY_CACHE_TTL_MS;
    // Recreate client with new key on next call
    this.client = null;
    return this.cachedApiKey;
  }
}

/**
 * Error class for Qdrant API errors
 */
export class QdrantError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly responseBody: string,
  ) {
    super(message);
    this.name = "QdrantError";
  }
}
