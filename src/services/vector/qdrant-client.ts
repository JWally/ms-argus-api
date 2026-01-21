// src/services/vector/qdrant-client.ts
// QDrant vector database client for ms-argus-vector integration
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import type { Logger } from "@aws-lambda-powertools/logger";

/**
 * QDrant client configuration
 */
export interface QdrantClientConfig {
  /** Base URL for QDrant REST API (e.g., http://alb-dns:6333) */
  baseUrl: string;
  /** ARN of the Secrets Manager secret containing the API key */
  secretArn: string;
  /** Logger instance for request logging */
  logger: Logger;
  /** Request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
}

/**
 * Vector search request
 */
export interface VectorSearchRequest {
  /** Query vector */
  vector: number[];
  /** Maximum number of results to return */
  limit: number;
  /** Include payload in results */
  with_payload?: boolean;
  /** Include vector in results */
  with_vector?: boolean;
  /** Score threshold for filtering results */
  score_threshold?: number;
  /** Filter conditions */
  filter?: QdrantFilter;
}

/**
 * QDrant filter for search queries
 */
export interface QdrantFilter {
  must?: QdrantCondition[];
  should?: QdrantCondition[];
  must_not?: QdrantCondition[];
}

/**
 * QDrant filter condition
 */
export interface QdrantCondition {
  key: string;
  match?: { value: string | number | boolean };
  range?: { gt?: number; gte?: number; lt?: number; lte?: number };
}

/**
 * Vector search result
 */
export interface VectorSearchResult {
  /** Point ID */
  id: string | number;
  /** Similarity score */
  score: number;
  /** Point payload */
  payload?: Record<string, unknown>;
  /** Point vector (if requested) */
  vector?: number[];
}

/**
 * Vector upsert request
 */
export interface VectorUpsertRequest {
  /** Points to upsert */
  points: VectorPoint[];
}

/**
 * Vector point for upsert
 */
export interface VectorPoint {
  /** Point ID (string or number) */
  id: string | number;
  /** Vector values */
  vector: number[];
  /** Optional payload */
  payload?: Record<string, unknown>;
}

/**
 * QDrant REST API response wrapper
 */
interface QdrantResponse<T> {
  result: T;
  status: string;
  time: number;
}

/**
 * QDrant client for vector operations
 * Communicates with QDrant via REST API through the internal ALB
 */
export class QdrantClient {
  private readonly config: Required<QdrantClientConfig>;
  private readonly secretsClient: SecretsManagerClient;
  private cachedApiKey: string | null = null;
  private apiKeyExpiresAt: number = 0;

  // Cache API key for 15 minutes to avoid Secrets Manager rate limits
  private static readonly API_KEY_CACHE_TTL_MS = 15 * 60 * 1000;

  constructor(config: QdrantClientConfig) {
    this.config = {
      ...config,
      timeoutMs: config.timeoutMs ?? 10000,
    };
    this.secretsClient = new SecretsManagerClient({});
  }

  /**
   * Search for similar vectors in a collection
   */
  async search(
    collection: string,
    request: VectorSearchRequest,
  ): Promise<VectorSearchResult[]> {
    const response = await this.request<QdrantResponse<VectorSearchResult[]>>(
      "POST",
      `/collections/${encodeURIComponent(collection)}/points/search`,
      request,
    );
    return response.result;
  }

  /**
   * Upsert vectors into a collection
   */
  async upsert(
    collection: string,
    request: VectorUpsertRequest,
  ): Promise<void> {
    await this.request<QdrantResponse<{ status: string }>>(
      "PUT",
      `/collections/${encodeURIComponent(collection)}/points`,
      request,
    );
  }

  /**
   * Delete points by IDs
   */
  async delete(collection: string, ids: (string | number)[]): Promise<void> {
    await this.request<QdrantResponse<{ status: string }>>(
      "POST",
      `/collections/${encodeURIComponent(collection)}/points/delete`,
      { points: ids },
    );
  }

  /**
   * Get points by IDs
   */
  async get(
    collection: string,
    ids: (string | number)[],
    options?: { with_payload?: boolean; with_vector?: boolean },
  ): Promise<VectorSearchResult[]> {
    const response = await this.request<QdrantResponse<VectorSearchResult[]>>(
      "POST",
      `/collections/${encodeURIComponent(collection)}/points`,
      {
        ids,
        with_payload: options?.with_payload ?? true,
        with_vector: options?.with_vector ?? false,
      },
    );
    return response.result;
  }

  /**
   * Check if a collection exists
   */
  async collectionExists(collection: string): Promise<boolean> {
    try {
      await this.request<QdrantResponse<unknown>>(
        "GET",
        `/collections/${encodeURIComponent(collection)}`,
      );
      return true;
    } catch (error) {
      if (error instanceof QdrantError && error.statusCode === 404) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Create a collection
   */
  async createCollection(
    collection: string,
    options: {
      vectors: {
        size: number;
        distance: "Cosine" | "Euclid" | "Dot";
      };
    },
  ): Promise<void> {
    await this.request<QdrantResponse<boolean>>(
      "PUT",
      `/collections/${encodeURIComponent(collection)}`,
      options,
    );
  }

  /**
   * Get the API key from Secrets Manager (with caching)
   */
  private async getApiKey(): Promise<string> {
    const now = Date.now();

    // Return cached key if still valid
    if (this.cachedApiKey && now < this.apiKeyExpiresAt) {
      return this.cachedApiKey;
    }

    // Fetch fresh key from Secrets Manager
    const response = await this.secretsClient.send(
      new GetSecretValueCommand({ SecretId: this.config.secretArn }),
    );

    if (!response.SecretString) {
      throw new Error("QDrant API key secret is empty");
    }

    this.cachedApiKey = response.SecretString;
    this.apiKeyExpiresAt = now + QdrantClient.API_KEY_CACHE_TTL_MS;

    return this.cachedApiKey;
  }

  /**
   * Make an HTTP request to QDrant
   */
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const apiKey = await this.getApiKey();
    const url = `${this.config.baseUrl}${path}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      this.config.timeoutMs,
    );

    try {
      this.config.logger.debug("QDrant request", { method, path });

      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "api-key": apiKey,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "");
        throw new QdrantError(
          `QDrant request failed: ${response.status} ${response.statusText}`,
          response.status,
          errorBody,
        );
      }

      const data = await response.json();
      return data as T;
    } catch (error) {
      if (error instanceof QdrantError) {
        throw error;
      }

      if (error instanceof Error && error.name === "AbortError") {
        throw new QdrantError(
          `QDrant request timed out after ${this.config.timeoutMs}ms`,
          0,
          "",
        );
      }

      throw new QdrantError(
        `QDrant request failed: ${error instanceof Error ? error.message : "Unknown error"}`,
        0,
        "",
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * QDrant-specific error class
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
