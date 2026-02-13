import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleSyncInvoke, isSyncInvokeRequest } from "./sync-handler";
import { QdrantError } from "../../services/vector/qdrant-client";
import type { SyncInvokeRequest } from "./types";

const mockQdrantClient = {
  search: vi.fn(),
  upsert: vi.fn(),
  collectionExists: vi.fn(),
  createCollection: vi.fn(),
  listCollections: vi.fn(),
  getCollectionInfo: vi.fn(),
  deleteCollection: vi.fn(),
};

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

const deps = {
  qdrantClient: mockQdrantClient as any,
  logger: mockLogger as any,
  metrics: mockMetrics as any,
};

describe("handleSyncInvoke", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockQdrantClient.collectionExists.mockResolvedValue(true);
  });

  it("should return error for missing action", async () => {
    const result = await handleSyncInvoke(null as any, deps);
    expect(result.success).toBe(false);
    expect((result as any).code).toBe("INVALID_REQUEST");
  });

  it("should return error for unknown action", async () => {
    const result = await handleSyncInvoke({ action: "bogus" } as any, deps);
    expect(result.success).toBe(false);
    expect((result as any).error).toContain("Unknown action");
  });

  describe("search", () => {
    it("should reject invalid vector dimensions", async () => {
      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: [1, 2, 3],
          collection: "test",
        } as SyncInvokeRequest,
        deps,
      );
      expect(result.success).toBe(false);
      expect((result as any).error).toContain("512 numbers");
    });

    it("should return search results", async () => {
      const vector = Array(512).fill(0.5);
      mockQdrantClient.search.mockResolvedValue([
        { id: "uuid-1", score: 0.95, payload: { device_id: "dev_001" } },
        { id: "uuid-2", score: 0.85, payload: { device_id: "dev_002" } },
      ]);

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector,
          collection: "test",
          limit: 5,
          score_threshold: 0.7,
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
      expect((result as any).results).toHaveLength(2);
      expect((result as any).results[0].device_id).toBe("dev_001");
    });

    it("should use payload device_id if available", async () => {
      const vector = Array(512).fill(0.5);
      mockQdrantClient.search.mockResolvedValue([
        { id: 12345, score: 0.9, payload: { device_id: "dev_from_payload" } },
      ]);

      const result = await handleSyncInvoke(
        { action: "search", vector, collection: "test" } as SyncInvokeRequest,
        deps,
      );

      expect((result as any).results[0].device_id).toBe("dev_from_payload");
    });

    it("should pass filter through to qdrant search", async () => {
      const vector = Array(512).fill(0.5);
      const filter = {
        must: [
          { key: "screen_width", range: { gte: 388, lte: 398 } },
          { key: "screen_height", range: { gte: 847, lte: 857 } },
        ],
      };
      mockQdrantClient.search.mockResolvedValue([]);

      await handleSyncInvoke(
        {
          action: "search",
          vector,
          collection: "test",
          filter,
        } as SyncInvokeRequest,
        deps,
      );

      expect(mockQdrantClient.search).toHaveBeenCalledWith("test", {
        vector,
        limit: 10,
        with_payload: true,
        score_threshold: 0.7,
        filter,
      });
    });

    it("should fall back to point ID string when no payload device_id", async () => {
      const vector = Array(512).fill(0.5);
      mockQdrantClient.search.mockResolvedValue([
        { id: "uuid-123", score: 0.9, payload: {} },
      ]);

      const result = await handleSyncInvoke(
        { action: "search", vector, collection: "test" } as SyncInvokeRequest,
        deps,
      );

      expect((result as any).results[0].device_id).toBe("uuid-123");
    });
  });

  describe("upsert", () => {
    it("should reject invalid vector", async () => {
      const result = await handleSyncInvoke(
        {
          action: "upsert",
          device_id: "dev_001",
          vector: [1],
          collection: "test",
        } as SyncInvokeRequest,
        deps,
      );
      expect(result.success).toBe(false);
    });

    it("should reject missing device_id", async () => {
      const result = await handleSyncInvoke(
        {
          action: "upsert",
          device_id: "",
          vector: Array(512).fill(0.5),
          collection: "test",
        } as SyncInvokeRequest,
        deps,
      );
      expect(result.success).toBe(false);
      expect((result as any).error).toContain("Missing device_id");
    });

    it("should upsert vector successfully", async () => {
      mockQdrantClient.upsert.mockResolvedValue(undefined);

      const result = await handleSyncInvoke(
        {
          action: "upsert",
          device_id: "dev_001",
          vector: Array(512).fill(0.5),
          collection: "test",
          payload: { user_agent: "Chrome" },
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
      expect((result as any).device_id).toBe("dev_001");
      expect(mockQdrantClient.upsert).toHaveBeenCalledTimes(1);
    });
  });

  describe("list_collections", () => {
    it("should list collections with info", async () => {
      mockQdrantClient.listCollections.mockResolvedValue(["col1", "col2"]);
      mockQdrantClient.getCollectionInfo
        .mockResolvedValueOnce({ points_count: 100, vectors_count: 100 })
        .mockResolvedValueOnce({ points_count: 50, vectors_count: 50 });

      const result = await handleSyncInvoke(
        { action: "list_collections" } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
      expect((result as any).collections).toHaveLength(2);
      expect((result as any).collections[0].points_count).toBe(100);
    });

    it("should handle getCollectionInfo failure gracefully", async () => {
      mockQdrantClient.listCollections.mockResolvedValue(["col1"]);
      mockQdrantClient.getCollectionInfo.mockRejectedValue(
        new Error("timeout"),
      );

      const result = await handleSyncInvoke(
        { action: "list_collections" } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
      expect((result as any).collections[0].points_count).toBe(0);
    });
  });

  describe("delete_collection", () => {
    it("should delete collection", async () => {
      mockQdrantClient.deleteCollection.mockResolvedValue(undefined);

      const result = await handleSyncInvoke(
        {
          action: "delete_collection",
          collection: "old-collection",
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
      expect((result as any).collection).toBe("old-collection");
    });
  });

  describe("auto_create_collection", () => {
    it("should auto-create collection when missing for search", async () => {
      mockQdrantClient.collectionExists.mockResolvedValue(false);
      mockQdrantClient.createCollection.mockResolvedValue(undefined);
      mockQdrantClient.search.mockResolvedValue([]);

      await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "new-col",
          auto_create_collection: true,
        } as SyncInvokeRequest,
        deps,
      );

      expect(mockQdrantClient.createCollection).toHaveBeenCalled();
    });

    it("should handle race condition on collection creation", async () => {
      mockQdrantClient.collectionExists.mockResolvedValue(false);
      mockQdrantClient.createCollection.mockRejectedValue(
        new Error("already exists"),
      );
      mockQdrantClient.search.mockResolvedValue([]);

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "new-col",
          auto_create_collection: true,
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(true);
    });

    it("should rethrow non-race-condition errors from createCollection", async () => {
      mockQdrantClient.collectionExists.mockResolvedValue(false);
      mockQdrantClient.createCollection.mockRejectedValue(
        new Error("disk full"),
      );

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "new-col",
          auto_create_collection: true,
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(false);
      expect((result as any).code).toBe("UNKNOWN");
    });
  });

  describe("error handling", () => {
    it("should handle QdrantError with 404", async () => {
      mockQdrantClient.search.mockRejectedValue(
        new QdrantError("not found", 404, ""),
      );

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "missing",
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(false);
      expect((result as any).code).toBe("COLLECTION_NOT_FOUND");
    });

    it("should handle QdrantError with generic error", async () => {
      mockQdrantClient.search.mockRejectedValue(
        new QdrantError("server error", 500, ""),
      );

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "test",
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(false);
      expect((result as any).code).toBe("QDRANT_ERROR");
    });

    it("should handle generic errors", async () => {
      mockQdrantClient.search.mockRejectedValue(new Error("oops"));

      const result = await handleSyncInvoke(
        {
          action: "search",
          vector: Array(512).fill(0.5),
          collection: "test",
        } as SyncInvokeRequest,
        deps,
      );

      expect(result.success).toBe(false);
      expect((result as any).code).toBe("UNKNOWN");
    });
  });
});

describe("isSyncInvokeRequest", () => {
  it("should return true for valid sync request", () => {
    expect(isSyncInvokeRequest({ action: "search" })).toBe(true);
  });

  it("should return false for null", () => {
    expect(isSyncInvokeRequest(null)).toBe(false);
  });

  it("should return false for non-object", () => {
    expect(isSyncInvokeRequest("string")).toBe(false);
  });

  it("should return false for object without action", () => {
    expect(isSyncInvokeRequest({ foo: "bar" })).toBe(false);
  });
});
