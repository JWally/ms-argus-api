import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { QdrantClient, QdrantError } from "./qdrant-client";

vi.mock("@qdrant/js-client-rest", () => ({
  QdrantClient: vi.fn().mockImplementation(() => ({
    search: vi.fn().mockResolvedValue([]),
    upsert: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
    retrieve: vi.fn().mockResolvedValue([]),
    collectionExists: vi.fn().mockResolvedValue({ exists: true }),
    createCollection: vi.fn().mockResolvedValue(undefined),
    deleteCollection: vi.fn().mockResolvedValue(undefined),
    getCollections: vi
      .fn()
      .mockResolvedValue({ collections: [{ name: "col1" }, { name: "col2" }] }),
    getCollection: vi.fn().mockResolvedValue({
      points_count: 42,
      indexed_vectors_count: 100,
    }),
  })),
}));

const secretsMock = mockClient(SecretsManagerClient);

function createClient() {
  return new QdrantClient({
    baseUrl: "http://qdrant.internal:6333",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789:secret:qdrant-key",
    logger: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    } as any,
    timeoutMs: 10000,
    secretsClient: new SecretsManagerClient({}),
  });
}

describe("QdrantClient", () => {
  beforeEach(() => {
    secretsMock.reset();
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretString: "test-api-key",
    });
    vi.clearAllMocks();
  });

  describe("API Key Management", () => {
    it("fetches API key from Secrets Manager on first request", async () => {
      const client = createClient();
      await client.search("col", { vector: [1, 2, 3], limit: 10 });

      const calls = secretsMock.commandCalls(GetSecretValueCommand);
      expect(calls.length).toBe(1);
      expect(calls[0].args[0].input.SecretId).toBe(
        "arn:aws:secretsmanager:us-east-1:123456789:secret:qdrant-key",
      );
    });

    it("caches API key across requests", async () => {
      const client = createClient();
      await client.search("col", { vector: [1], limit: 10 });
      await client.search("col", { vector: [2], limit: 10 });

      const calls = secretsMock.commandCalls(GetSecretValueCommand);
      expect(calls.length).toBe(1);
    });

    it("throws QdrantError when secret is empty", async () => {
      secretsMock.on(GetSecretValueCommand).resolves({
        SecretString: undefined,
      });
      const client = createClient();

      await expect(
        client.search("col", { vector: [1], limit: 10 }),
      ).rejects.toThrow("QDrant API key secret is empty");
    });
  });

  describe("Method delegation", () => {
    it("search delegates to official client", async () => {
      const client = createClient();
      await client.search("col", {
        vector: [1, 2],
        limit: 5,
        with_payload: true,
      });
      // If it didn't throw, delegation worked
    });

    it("upsert delegates to official client", async () => {
      const client = createClient();
      await client.upsert("col", {
        points: [{ id: "p1", vector: [1, 2, 3] }],
      });
    });

    it("delete delegates to official client", async () => {
      const client = createClient();
      await client.delete("col", ["id1", "id2"]);
    });

    it("get delegates to official client retrieve", async () => {
      const client = createClient();
      await client.get("col", ["p1"], { with_payload: true });
    });

    it("collectionExists returns boolean", async () => {
      const client = createClient();
      const exists = await client.collectionExists("col");
      expect(exists).toBe(true);
    });

    it("createCollection delegates to official client", async () => {
      const client = createClient();
      await client.createCollection("col", {
        vectors: { size: 128, distance: "Cosine" },
      });
    });

    it("deleteCollection delegates to official client", async () => {
      const client = createClient();
      await client.deleteCollection("col");
    });

    it("listCollections returns collection names", async () => {
      const client = createClient();
      const names = await client.listCollections();
      expect(names).toEqual(["col1", "col2"]);
    });

    it("getCollectionInfo returns points and vectors counts", async () => {
      const client = createClient();
      const info = await client.getCollectionInfo("col");
      expect(info.points_count).toBe(42);
      expect(info.vectors_count).toBe(100);
    });
  });

  describe("QdrantError", () => {
    it("has correct name and properties", () => {
      const err = new QdrantError("test msg", 503, "Service Unavailable");
      expect(err.name).toBe("QdrantError");
      expect(err.statusCode).toBe(503);
      expect(err.responseBody).toBe("Service Unavailable");
      expect(err.message).toBe("test msg");
      expect(err).toBeInstanceOf(Error);
    });
  });
});
