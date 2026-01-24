// Thin wrapper around @qdrant/js-client-rest with AWS Secrets Manager auth
import { QdrantClient as OfficialClient } from "@qdrant/js-client-rest";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import type { Logger } from "@aws-lambda-powertools/logger";

export interface QdrantClientConfig {
  baseUrl: string;
  secretArn: string;
  logger: Logger;
  timeoutMs?: number;
  secretsClient?: SecretsManagerClient;
}

export interface VectorSearchRequest {
  vector: number[];
  limit: number;
  with_payload?: boolean;
  with_vector?: boolean;
  score_threshold?: number;
  filter?: QdrantFilter;
}

export interface QdrantFilter {
  must?: QdrantCondition[];
  should?: QdrantCondition[];
  must_not?: QdrantCondition[];
}

export interface QdrantCondition {
  key: string;
  match?: { value: string | number | boolean };
  range?: { gt?: number; gte?: number; lt?: number; lte?: number };
}

export interface VectorSearchResult {
  id: string | number;
  score: number;
  payload?: Record<string, unknown>;
  vector?: number[];
}

export interface VectorUpsertRequest {
  points: VectorPoint[];
}

export interface VectorPoint {
  id: string | number;
  vector: number[];
  payload?: Record<string, unknown>;
}

export class QdrantClient {
  private readonly secretsClient: SecretsManagerClient;
  private readonly config: QdrantClientConfig;
  private client: OfficialClient | null = null;
  private cachedApiKey: string | null = null;
  private apiKeyExpiresAt = 0;
  private static readonly API_KEY_CACHE_TTL_MS = 15 * 60 * 1000;

  constructor(config: QdrantClientConfig) {
    this.config = config;
    this.secretsClient = config.secretsClient ?? new SecretsManagerClient({});
  }

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

  async upsert(
    collection: string,
    request: VectorUpsertRequest,
  ): Promise<void> {
    const client = await this.getClient();
    await client.upsert(collection, { points: request.points });
  }

  async delete(collection: string, ids: (string | number)[]): Promise<void> {
    const client = await this.getClient();
    await client.delete(collection, { points: ids });
  }

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

  async collectionExists(collection: string): Promise<boolean> {
    const client = await this.getClient();
    const result = await client.collectionExists(collection);
    return result.exists;
  }

  async createCollection(
    collection: string,
    options: {
      vectors: { size: number; distance: "Cosine" | "Euclid" | "Dot" };
    },
  ): Promise<void> {
    const client = await this.getClient();
    await client.createCollection(collection, options);
  }

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
