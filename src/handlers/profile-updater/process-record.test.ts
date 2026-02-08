import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../services/vector/embedding", () => ({
  computeEmbedding: vi.fn().mockReturnValue({
    vector: Array(256).fill(0.5),
    dimensions: 256,
  }),
  EMBEDDING_VERSION: "v2",
}));

import { mockClient } from "aws-sdk-client-mock";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import type { SQSRecord } from "aws-lambda";
import { processRecord } from "./process-record";
import type { ProfileService } from "../../services/profile";

const sqsMock = mockClient(SQSClient);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

function createSQSRecord(body: object | string): SQSRecord {
  return {
    messageId: "test-msg-1",
    receiptHandle: "test-receipt",
    body: typeof body === "string" ? body : JSON.stringify(body),
    attributes: {
      ApproximateReceiveCount: "1",
      SentTimestamp: "1704067200000",
      SenderId: "123456789",
      ApproximateFirstReceiveTimestamp: "1704067200001",
    },
    messageAttributes: {},
    md5OfBody: "test-md5",
    eventSource: "aws:sqs",
    eventSourceARN: "arn:aws:sqs:us-east-1:123456789:test-queue",
    awsRegion: "us-east-1",
  };
}

const validPayload = {
  device_id: "dev_001",
  fingerprint: {
    stable_hash: "hash-abc",
    fuzzy_hash: "fuzzy-def",
    canvas_hash: "canvas-123",
    ip_address: "1.1.1.1",
  },
  match_result: { confidence: 0.95 },
};

describe("processRecord", () => {
  let mockService: ProfileService;

  beforeEach(() => {
    sqsMock.reset();
    sqsMock.on(SendMessageCommand).resolves({});
    vi.clearAllMocks();
    mockService = {
      processProfileUpdate: vi
        .fn()
        .mockResolvedValue({ skipped: false, tier1Writes: 2 }),
    } as unknown as ProfileService;
  });

  it("should process a valid record and record write metrics", async () => {
    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(mockService.processProfileUpdate).toHaveBeenCalledTimes(1);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "ProfileWrite",
      expect.any(String),
      1,
    );
  });

  it("should handle malformed JSON", async () => {
    const record = createSQSRecord("{bad json");
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(mockService.processProfileUpdate).not.toHaveBeenCalled();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "MalformedPayload",
      expect.any(String),
      1,
    );
  });

  it("should record skip metrics for mutation_gate", async () => {
    vi.mocked(mockService.processProfileUpdate).mockResolvedValue({
      skipped: true,
      reason: "mutation_gate",
    });

    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "MutationGateSkip",
      expect.any(String),
      1,
    );
  });

  it("should record skip metrics for no_drift with tier2 writes", async () => {
    vi.mocked(mockService.processProfileUpdate).mockResolvedValue({
      skipped: true,
      reason: "no_drift",
    });

    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "NoDriftSkip",
      expect.any(String),
      1,
    );
  });

  it("should queue vector upsert when SQS is configured", async () => {
    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: new SQSClient({}),
      vectorQueueUrl: "https://sqs.us-east-1.amazonaws.com/123/vector-queue",
    });

    expect(sqsMock.commandCalls(SendMessageCommand)).toHaveLength(1);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "VectorUpsertQueued",
      expect.any(String),
      1,
    );
  });

  it("should not queue vector upsert when SQS is not configured", async () => {
    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(sqsMock.commandCalls(SendMessageCommand)).toHaveLength(0);
  });

  it("should handle vector queue error gracefully", async () => {
    sqsMock.on(SendMessageCommand).rejects(new Error("SQS error"));

    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: new SQSClient({}),
      vectorQueueUrl: "https://sqs.us-east-1.amazonaws.com/123/vector-queue",
    });

    // Should not throw
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "VectorUpsertQueueError",
      expect.any(String),
      1,
    );
  });

  it("should record no_drift skip without tier2 writes", async () => {
    vi.mocked(mockService.processProfileUpdate).mockResolvedValue({
      skipped: true,
      reason: "no_drift",
    });

    const record = createSQSRecord(validPayload);
    await processRecord(record, mockService, {
      logger: mockLogger as any,
      metrics: mockMetrics as any,
      sqsClient: null,
    });

    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "NoDriftSkip",
      expect.any(String),
      1,
    );
  });
});
