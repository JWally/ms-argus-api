import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import type { SQSEvent, SQSRecord } from "aws-lambda";

vi.hoisted(() => {
  process.env.QDRANT_URL = "http://qdrant.internal:6333";
  process.env.QDRANT_SECRET_ARN =
    "arn:aws:secretsmanager:us-east-1:123:secret:test";
  process.env.POWERTOOLS_SERVICE_NAME = "argus-vector-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "ArgusTest";
});

const mockSearch = vi.fn();
const mockUpsert = vi.fn();

vi.mock("../services/vector/qdrant-client", () => ({
  QdrantClient: vi.fn().mockImplementation(() => ({
    search: mockSearch,
    upsert: mockUpsert,
  })),
}));

vi.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: vi.fn().mockImplementation(() => ({})),
}));

vi.mock("@aws-lambda-powertools/logger", () => ({
  Logger: vi.fn().mockImplementation(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: vi.fn(),
    publishStoredMetrics: vi.fn(),
  })),
  MetricUnit: { Count: "Count", Milliseconds: "Milliseconds" },
}));

function createSQSRecord(body: unknown, messageId = "msg-1"): SQSRecord {
  return {
    messageId,
    receiptHandle: "receipt-1",
    body: typeof body === "string" ? body : JSON.stringify(body),
    attributes: {
      ApproximateReceiveCount: "1",
      SentTimestamp: "1234567890",
      SenderId: "sender",
      ApproximateFirstReceiveTimestamp: "1234567890",
    },
    messageAttributes: {},
    md5OfBody: "md5",
    eventSource: "aws:sqs",
    eventSourceARN: "arn:aws:sqs:us-east-1:123:queue",
    awsRegion: "us-east-1",
  };
}

function createSQSEvent(records: SQSRecord[]): SQSEvent {
  return { Records: records };
}

describe("Vector Worker Handler", () => {
  let handler: any;

  beforeEach(async () => {
    mockSearch.mockReset();
    mockUpsert.mockReset();
    mockSearch.mockResolvedValue([]);
    mockUpsert.mockResolvedValue(undefined);

    const module = await import("./vector-worker");
    handler = module.handler;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Basic SQS Handling", () => {
    it("processes empty batch successfully", async () => {
      const event = createSQSEvent([]);
      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([]);
    });

    it("returns no failures for successful processing", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          type: "search",
          session_id: "sess-1",
          device_id: "dev-1",
          vector: [1, 2, 3],
          collection: "fingerprints",
        }),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([]);
    });

    it("returns failure for records that throw", async () => {
      mockSearch.mockRejectedValue(new Error("QDrant unavailable"));

      const event = createSQSEvent([
        createSQSRecord(
          {
            type: "search",
            session_id: "sess-1",
            device_id: "dev-1",
            vector: [1, 2, 3],
            collection: "fingerprints",
          },
          "fail-msg-1",
        ),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([
        { itemIdentifier: "fail-msg-1" },
      ]);
    });

    it("processes multiple records and reports individual failures", async () => {
      mockSearch
        .mockResolvedValueOnce([])
        .mockRejectedValueOnce(new Error("fail"));

      const event = createSQSEvent([
        createSQSRecord(
          {
            type: "search",
            session_id: "s1",
            device_id: "d1",
            vector: [1],
            collection: "col",
          },
          "msg-ok",
        ),
        createSQSRecord(
          {
            type: "search",
            session_id: "s2",
            device_id: "d2",
            vector: [2],
            collection: "col",
          },
          "msg-fail",
        ),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([
        { itemIdentifier: "msg-fail" },
      ]);
    });
  });

  describe("Warmup Messages", () => {
    it("handles warmup message without calling QDrant", async () => {
      const event = createSQSEvent([
        createSQSRecord({ warmup: true, source: "eventbridge" }),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([]);
      expect(mockSearch).not.toHaveBeenCalled();
      expect(mockUpsert).not.toHaveBeenCalled();
    });

    it("treats warmup: false as non-warmup", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          warmup: false,
          type: "search",
          session_id: "s",
          device_id: "d",
          vector: [1],
          collection: "c",
        }),
      ]);

      await handler(event, {} as any, vi.fn());
      expect(mockSearch).toHaveBeenCalled();
    });
  });

  describe("Search Messages", () => {
    it("calls QDrant search with correct parameters", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          type: "search",
          session_id: "sess-1",
          device_id: "dev-1",
          vector: [0.1, 0.2, 0.3, 0.4],
          collection: "fingerprints",
          limit: 5,
        }),
      ]);

      await handler(event, {} as any, vi.fn());

      expect(mockSearch).toHaveBeenCalledWith("fingerprints", {
        vector: [0.1, 0.2, 0.3, 0.4],
        limit: 5,
        with_payload: true,
      });
    });

    it("defaults limit to 10 when not specified", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          type: "search",
          session_id: "sess-1",
          device_id: "dev-1",
          vector: [1, 2, 3],
          collection: "col",
        }),
      ]);

      await handler(event, {} as any, vi.fn());

      expect(mockSearch).toHaveBeenCalledWith("col", {
        vector: [1, 2, 3],
        limit: 10,
        with_payload: true,
      });
    });
  });

  describe("Upsert Messages", () => {
    it("calls QDrant upsert with correct parameters", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          type: "upsert",
          device_id: "dev-1",
          vector: [0.5, 0.6, 0.7],
          collection: "fingerprints",
          payload: { stable_hash: "abc123" },
        }),
      ]);

      await handler(event, {} as any, vi.fn());

      expect(mockUpsert).toHaveBeenCalledWith("fingerprints", {
        points: [
          {
            id: "dev-1",
            vector: [0.5, 0.6, 0.7],
            payload: { stable_hash: "abc123" },
          },
        ],
      });
    });

    it("handles upsert without payload", async () => {
      const event = createSQSEvent([
        createSQSRecord({
          type: "upsert",
          device_id: "dev-1",
          vector: [1, 2, 3],
          collection: "col",
        }),
      ]);

      await handler(event, {} as any, vi.fn());

      expect(mockUpsert).toHaveBeenCalledWith("col", {
        points: [
          {
            id: "dev-1",
            vector: [1, 2, 3],
            payload: undefined,
          },
        ],
      });
    });
  });

  describe("Malformed Messages", () => {
    it("does not retry malformed JSON", async () => {
      const event = createSQSEvent([
        createSQSRecord("not valid json {{{", "bad-json-msg"),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([]);
    });

    it("does not retry unknown message types", async () => {
      const event = createSQSEvent([
        createSQSRecord({ type: "unknown_operation", data: {} }),
      ]);

      const result = await handler(event, {} as any, vi.fn());
      expect(result.batchItemFailures).toEqual([]);
    });
  });
});
