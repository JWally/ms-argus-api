// src/services/vector/qdrant-client.test.ts
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { QdrantClient, QdrantError } from "./qdrant-client";

// Mock SecretsManager
const secretsMock = mockClient(SecretsManagerClient);

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function createClient(overrides: Partial<{ timeoutMs: number }> = {}) {
  return new QdrantClient({
    baseUrl: "http://qdrant.internal:6333",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789:secret:qdrant-key",
    logger: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    } as any,
    timeoutMs: overrides.timeoutMs ?? 10000,
    secretsClient: new SecretsManagerClient({}),
  });
}

function mockSecretResponse(key: string = "test-api-key") {
  secretsMock.on(GetSecretValueCommand).resolves({
    SecretString: key,
  });
}

function mockFetchResponse(body: unknown, status = 200) {
  mockFetch.mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

describe("QdrantClient", () => {
  beforeEach(() => {
    secretsMock.reset();
    mockFetch.mockReset();
    mockSecretResponse();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ==================== API KEY MANAGEMENT ====================

  describe("API Key Management", () => {
    it("fetches API key from Secrets Manager on first request", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("test-collection", { vector: [1, 2, 3], limit: 10 });

      const calls = secretsMock.commandCalls(GetSecretValueCommand);
      expect(calls.length).toBe(1);
      expect(calls[0].args[0].input.SecretId).toBe(
        "arn:aws:secretsmanager:us-east-1:123456789:secret:qdrant-key",
      );
    });

    it("caches API key across requests", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("test-collection", { vector: [1, 2, 3], limit: 10 });
      await client.search("test-collection", { vector: [4, 5, 6], limit: 10 });

      const calls = secretsMock.commandCalls(GetSecretValueCommand);
      expect(calls.length).toBe(1); // Only fetched once
    });

    it("throws when secret is empty", async () => {
      secretsMock.on(GetSecretValueCommand).resolves({
        SecretString: undefined,
      });
      const client = createClient();

      await expect(
        client.search("test-collection", { vector: [1, 2, 3], limit: 10 }),
      ).rejects.toThrow("QDrant API key secret is empty");
    });

    it("passes API key in request headers", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("test-collection", { vector: [1, 2, 3], limit: 10 });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            "api-key": "test-api-key",
          }),
        }),
      );
    });
  });

  // ==================== SEARCH ====================

  describe("search", () => {
    it("sends POST to correct endpoint", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("my-collection", { vector: [1, 2, 3], limit: 5 });

      expect(mockFetch).toHaveBeenCalledWith(
        "http://qdrant.internal:6333/collections/my-collection/points/search",
        expect.objectContaining({ method: "POST" }),
      );
    });

    it("sends request body with vector and limit", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("col", {
        vector: [1.0, 2.0, 3.0],
        limit: 10,
        with_payload: true,
        score_threshold: 0.8,
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.vector).toEqual([1.0, 2.0, 3.0]);
      expect(body.limit).toBe(10);
      expect(body.with_payload).toBe(true);
      expect(body.score_threshold).toBe(0.8);
    });

    it("returns search results", async () => {
      const client = createClient();
      const results = [
        { id: "point-1", score: 0.95, payload: { device_id: "dev-1" } },
        { id: "point-2", score: 0.87, payload: { device_id: "dev-2" } },
      ];
      mockFetchResponse({ result: results, status: "ok", time: 0.05 });

      const response = await client.search("col", {
        vector: [1, 2, 3],
        limit: 10,
      });

      expect(response).toEqual(results);
      expect(response[0].score).toBe(0.95);
    });

    it("encodes collection name", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("collection with spaces", {
        vector: [1],
        limit: 1,
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining("collection%20with%20spaces"),
        expect.any(Object),
      );
    });
  });

  // ==================== UPSERT ====================

  describe("upsert", () => {
    it("sends PUT to correct endpoint", async () => {
      const client = createClient();
      mockFetchResponse({ result: { status: "ok" }, status: "ok", time: 0.1 });

      await client.upsert("my-collection", {
        points: [{ id: "p1", vector: [1, 2, 3] }],
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "http://qdrant.internal:6333/collections/my-collection/points",
        expect.objectContaining({ method: "PUT" }),
      );
    });

    it("sends points in request body", async () => {
      const client = createClient();
      mockFetchResponse({ result: { status: "ok" }, status: "ok", time: 0.1 });

      await client.upsert("col", {
        points: [
          { id: "p1", vector: [1, 2], payload: { name: "test" } },
          { id: "p2", vector: [3, 4] },
        ],
      });

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.points.length).toBe(2);
      expect(body.points[0].payload).toEqual({ name: "test" });
    });
  });

  // ==================== DELETE ====================

  describe("delete", () => {
    it("sends POST to delete endpoint with point IDs", async () => {
      const client = createClient();
      mockFetchResponse({ result: { status: "ok" }, status: "ok", time: 0.1 });

      await client.delete("col", ["id1", "id2", 123]);

      expect(mockFetch).toHaveBeenCalledWith(
        "http://qdrant.internal:6333/collections/col/points/delete",
        expect.objectContaining({ method: "POST" }),
      );
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.points).toEqual(["id1", "id2", 123]);
    });
  });

  // ==================== GET ====================

  describe("get", () => {
    it("retrieves points by IDs", async () => {
      const client = createClient();
      const results = [{ id: "p1", score: 1.0, payload: { key: "val" } }];
      mockFetchResponse({ result: results, status: "ok", time: 0.1 });

      const response = await client.get("col", ["p1"], {
        with_payload: true,
        with_vector: false,
      });

      expect(response).toEqual(results);
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.ids).toEqual(["p1"]);
      expect(body.with_payload).toBe(true);
      expect(body.with_vector).toBe(false);
    });

    it("defaults with_payload to true and with_vector to false", async () => {
      const client = createClient();
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.get("col", ["p1"]);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.with_payload).toBe(true);
      expect(body.with_vector).toBe(false);
    });
  });

  // ==================== COLLECTION EXISTS ====================

  describe("collectionExists", () => {
    it("returns true when collection exists", async () => {
      const client = createClient();
      mockFetchResponse({
        result: { status: "green" },
        status: "ok",
        time: 0.1,
      });

      const exists = await client.collectionExists("my-col");
      expect(exists).toBe(true);
    });

    it("returns false on 404", async () => {
      const client = createClient();
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: () => Promise.resolve("Not found"),
      });

      const exists = await client.collectionExists("missing-col");
      expect(exists).toBe(false);
    });

    it("throws on non-404 errors", async () => {
      const client = createClient();
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        text: () => Promise.resolve("Server error"),
      });

      await expect(client.collectionExists("broken-col")).rejects.toThrow(
        QdrantError,
      );
    });
  });

  // ==================== CREATE COLLECTION ====================

  describe("createCollection", () => {
    it("sends PUT with vector config", async () => {
      const client = createClient();
      mockFetchResponse({ result: true, status: "ok", time: 0.1 });

      await client.createCollection("new-col", {
        vectors: { size: 128, distance: "Cosine" },
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "http://qdrant.internal:6333/collections/new-col",
        expect.objectContaining({ method: "PUT" }),
      );
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.vectors.size).toBe(128);
      expect(body.vectors.distance).toBe("Cosine");
    });
  });

  // ==================== ERROR HANDLING ====================

  describe("Error Handling", () => {
    it("throws QdrantError on non-2xx responses", async () => {
      const client = createClient();
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: () => Promise.resolve("Invalid vector dimensions"),
      });

      try {
        await client.search("col", { vector: [1], limit: 1 });
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(QdrantError);
        expect((err as QdrantError).statusCode).toBe(400);
        expect((err as QdrantError).responseBody).toBe(
          "Invalid vector dimensions",
        );
      }
    });

    it("throws QdrantError on timeout (AbortError)", async () => {
      const client = createClient({ timeoutMs: 1 }); // Very short timeout
      mockFetch.mockImplementation(() => {
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        return Promise.reject(err);
      });

      try {
        await client.search("col", { vector: [1], limit: 1 });
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(QdrantError);
        expect((err as QdrantError).message).toContain("timed out");
      }
    });

    it("throws QdrantError on network errors", async () => {
      const client = createClient();
      mockFetch.mockRejectedValue(new Error("ECONNREFUSED"));

      try {
        await client.search("col", { vector: [1], limit: 1 });
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(QdrantError);
        expect((err as QdrantError).message).toContain("ECONNREFUSED");
        expect((err as QdrantError).statusCode).toBe(0);
      }
    });

    it("handles response.text() failure gracefully", async () => {
      const client = createClient();
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Error",
        text: () => Promise.reject(new Error("body read error")),
      });

      try {
        await client.search("col", { vector: [1], limit: 1 });
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(QdrantError);
        expect((err as QdrantError).statusCode).toBe(500);
        expect((err as QdrantError).responseBody).toBe("");
      }
    });
  });

  // ==================== TIMEOUT CONFIGURATION ====================

  describe("Timeout Configuration", () => {
    it("uses default timeout of 10000ms", async () => {
      const client = new QdrantClient({
        baseUrl: "http://localhost:6333",
        secretArn: "arn:test",
        logger: { debug: vi.fn() } as any,
        secretsClient: new SecretsManagerClient({}),
      });
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("col", { vector: [1], limit: 1 });

      // Verify AbortController signal was passed
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        }),
      );
    });

    it("uses custom timeout when provided", async () => {
      const client = createClient({ timeoutMs: 5000 });
      mockFetchResponse({ result: [], status: "ok", time: 0.1 });

      await client.search("col", { vector: [1], limit: 1 });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        }),
      );
    });
  });

  // ==================== QdrantError ====================

  describe("QdrantError", () => {
    it("has correct name", () => {
      const err = new QdrantError("test", 400, "body");
      expect(err.name).toBe("QdrantError");
    });

    it("exposes statusCode and responseBody", () => {
      const err = new QdrantError("msg", 503, "Service Unavailable");
      expect(err.statusCode).toBe(503);
      expect(err.responseBody).toBe("Service Unavailable");
      expect(err.message).toBe("msg");
    });

    it("is instanceof Error", () => {
      const err = new QdrantError("test", 0, "");
      expect(err).toBeInstanceOf(Error);
    });
  });
});
