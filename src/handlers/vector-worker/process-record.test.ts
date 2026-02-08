import { describe, it, expect, beforeEach, vi } from "vitest";
import { processRecord } from "./process-record";
import type { SQSRecord } from "aws-lambda";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { mockClient } from "aws-sdk-client-mock";

const sqsMock = mockClient(SQSClient);

const mockQdrantClient = {
  search: vi.fn(),
  upsert: vi.fn(),
};

function createMockDeps(overrides = {}) {
  return {
    qdrantClient: mockQdrantClient as never,
    sqs: new SQSClient({}),
    vectorResultsQueueUrl: "https://sqs.us-east-1.amazonaws.com/123/results",
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    } as any,
    metrics: {
      addMetric: vi.fn(),
    } as any,
    ...overrides,
  };
}

function createRecord(body: string): SQSRecord {
  return {
    messageId: "msg-123",
    receiptHandle: "receipt-123",
    body,
    attributes: {} as never,
    messageAttributes: {},
    md5OfBody: "",
    eventSource: "aws:sqs",
    eventSourceARN: "arn:aws:sqs:us-east-1:123:queue",
    awsRegion: "us-east-1",
  };
}

describe("processRecord", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sqsMock.reset();
    mockQdrantClient.search.mockReset();
    mockQdrantClient.upsert.mockReset();
  });

  it("should skip malformed JSON with error metric", async () => {
    const deps = createMockDeps();
    const record = createRecord("not valid json{{{");

    await processRecord(record, deps);

    expect(deps.logger.error).toHaveBeenCalledWith(
      expect.stringContaining("Malformed JSON"),
      expect.objectContaining({ messageId: "msg-123" }),
    );
    expect(deps.metrics.addMetric).toHaveBeenCalledWith(
      "MalformedPayload",
      expect.anything(),
      1,
    );
  });

  it("should skip warmup messages", async () => {
    const deps = createMockDeps();
    const record = createRecord(JSON.stringify({ warmup: true }));

    await processRecord(record, deps);

    expect(deps.logger.info).toHaveBeenCalledWith(
      expect.stringContaining("Warmup"),
    );
    expect(deps.metrics.addMetric).toHaveBeenCalledWith(
      "WarmupPing",
      expect.anything(),
      1,
    );
  });

  it("should skip messages without type field", async () => {
    const deps = createMockDeps();
    const record = createRecord(JSON.stringify({ foo: "bar" }));

    await processRecord(record, deps);

    expect(deps.logger.warn).toHaveBeenCalledWith(
      "Unknown message format",
      expect.anything(),
    );
    expect(deps.metrics.addMetric).toHaveBeenCalledWith(
      "UnknownMessageType",
      expect.anything(),
      1,
    );
  });

  describe("type: search", () => {
    it("should call Qdrant search and publish results to SQS", async () => {
      const deps = createMockDeps();
      const searchResults = [
        { id: "dev_1", score: 0.95, payload: { name: "device1" } },
        { id: "dev_2", score: 0.85, payload: { name: "device2" } },
      ];
      mockQdrantClient.search.mockResolvedValue(searchResults);
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "result-msg" });

      const record = createRecord(
        JSON.stringify({
          type: "search",
          session_id: "sess-123",
          device_id: "dev_caller",
          vector: [0.1, 0.2, 0.3],
          collection: "devices",
          limit: 5,
        }),
      );

      await processRecord(record, deps);

      expect(mockQdrantClient.search).toHaveBeenCalledWith("devices", {
        vector: [0.1, 0.2, 0.3],
        limit: 5,
        with_payload: true,
      });

      expect(deps.metrics.addMetric).toHaveBeenCalledWith(
        "VectorSearchComplete",
        expect.anything(),
        1,
      );
      expect(deps.metrics.addMetric).toHaveBeenCalledWith(
        "VectorSearchResultCount",
        expect.anything(),
        2,
      );

      // Check SQS publish
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls).toHaveLength(1);
      const body = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(body.session_id).toBe("sess-123");
      expect(body.results).toHaveLength(2);
      expect(body.collection).toBe("devices");
    });

    it("should skip SQS publish when vectorResultsQueueUrl is not set", async () => {
      const deps = createMockDeps({ vectorResultsQueueUrl: undefined });
      mockQdrantClient.search.mockResolvedValue([
        { id: "dev_1", score: 0.9, payload: {} },
      ]);

      const record = createRecord(
        JSON.stringify({
          type: "search",
          session_id: "sess-123",
          device_id: "dev_caller",
          vector: [0.1, 0.2],
          collection: "devices",
        }),
      );

      await processRecord(record, deps);

      expect(mockQdrantClient.search).toHaveBeenCalled();
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls).toHaveLength(0);
    });

    it("should default limit to 10 when not specified", async () => {
      const deps = createMockDeps();
      mockQdrantClient.search.mockResolvedValue([]);

      const record = createRecord(
        JSON.stringify({
          type: "search",
          session_id: "sess-123",
          device_id: "dev_caller",
          vector: [0.1],
          collection: "devices",
        }),
      );

      await processRecord(record, deps);

      expect(mockQdrantClient.search).toHaveBeenCalledWith(
        "devices",
        expect.objectContaining({ limit: 10 }),
      );
    });
  });

  describe("type: upsert", () => {
    it("should call Qdrant upsert with correct params", async () => {
      const deps = createMockDeps();
      mockQdrantClient.upsert.mockResolvedValue(undefined);

      const record = createRecord(
        JSON.stringify({
          type: "upsert",
          device_id: "dev_abc",
          vector: [0.5, 0.6, 0.7],
          collection: "devices",
          payload: { browser: "chrome" },
        }),
      );

      await processRecord(record, deps);

      expect(mockQdrantClient.upsert).toHaveBeenCalledWith("devices", {
        points: [
          {
            id: "dev_abc",
            vector: [0.5, 0.6, 0.7],
            payload: { browser: "chrome" },
          },
        ],
      });

      expect(deps.metrics.addMetric).toHaveBeenCalledWith(
        "VectorUpsertComplete",
        expect.anything(),
        1,
      );
    });
  });

  it("should log warning for unknown message type", async () => {
    const deps = createMockDeps();
    const record = createRecord(
      JSON.stringify({ type: "delete", id: "something" }),
    );

    await processRecord(record, deps);

    expect(deps.logger.warn).toHaveBeenCalledWith(
      "Unknown message type",
      expect.anything(),
    );
    expect(deps.metrics.addMetric).toHaveBeenCalledWith(
      "UnknownMessageType",
      expect.anything(),
      1,
    );
  });

  it("should emit VectorOperationDuration metric for valid operations", async () => {
    const deps = createMockDeps();
    mockQdrantClient.upsert.mockResolvedValue(undefined);

    const record = createRecord(
      JSON.stringify({
        type: "upsert",
        device_id: "dev_abc",
        vector: [0.1],
        collection: "devices",
      }),
    );

    await processRecord(record, deps);

    expect(deps.metrics.addMetric).toHaveBeenCalledWith(
      "VectorOperationDuration",
      expect.anything(),
      expect.any(Number),
    );
  });
});
