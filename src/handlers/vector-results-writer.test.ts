import { describe, it, expect, beforeEach, vi } from "vitest";

const { mockAddMetric, mockPublishStoredMetrics } = vi.hoisted(() => ({
  mockAddMetric: vi.fn(),
  mockPublishStoredMetrics: vi.fn(),
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: mockAddMetric,
    publishStoredMetrics: mockPublishStoredMetrics,
  })),
  MetricUnit: { Count: "Count", Milliseconds: "Milliseconds" },
}));

vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-vector-results-writer-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.VECTOR_RESULTS_TABLE = "test-vector-results";
});

import { mockClient } from "aws-sdk-client-mock";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import type { SQSEvent, SQSRecord, Context } from "aws-lambda";

const dynamoMock = mockClient(DynamoDBClient);

import { handler } from "./vector-results-writer";

describe("vector-results-writer handler", () => {
  const mockContext: Context = {
    callbackWaitsForEmptyEventLoop: false,
    functionName: "test-function",
    functionVersion: "1",
    invokedFunctionArn: "arn:aws:lambda:us-east-1:123456789:function:test",
    memoryLimitInMB: "256",
    awsRequestId: "test-request-id",
    logGroupName: "/aws/lambda/test",
    logStreamName: "2025/01/01/[$LATEST]test",
    getRemainingTimeInMillis: () => 30000,
    done: () => {},
    fail: () => {},
    succeed: () => {},
  };

  beforeEach(() => {
    dynamoMock.reset();
    dynamoMock.on(PutItemCommand).resolves({});
    vi.clearAllMocks();
  });

  const createSQSRecord = (
    body: string | object,
    messageId = "test-msg-1",
  ): SQSRecord => ({
    messageId,
    receiptHandle: "test-receipt-handle",
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
  });

  const createSQSEvent = (records: SQSRecord[]): SQSEvent => ({
    Records: records,
  });

  const validMessage = {
    session_id: "session-123",
    results: [
      { id: "dev_001", score: 0.95, payload: { device_id: "dev_001" } },
      { id: "dev_002", score: 0.82 },
    ],
    collection: "fingerprints_v2",
    timestamp: 1704067200000,
  };

  it("should write valid vector results to DynamoDB", async () => {
    const event = createSQSEvent([createSQSRecord(validMessage)]);
    await handler(event, mockContext, () => {});

    const putCalls = dynamoMock.commandCalls(PutItemCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input.TableName).toBe("test-vector-results");
  });

  it("should skip warmup messages", async () => {
    const event = createSQSEvent([
      createSQSRecord({ warmup: true, source: "warmup-rule" }),
    ]);
    await handler(event, mockContext, () => {});

    expect(dynamoMock.commandCalls(PutItemCommand)).toHaveLength(0);
    expect(mockAddMetric).toHaveBeenCalledWith("WarmupPing", "Count", 1);
  });

  it("should handle malformed JSON", async () => {
    const event = createSQSEvent([createSQSRecord("{bad json", "bad-msg")]);
    await handler(event, mockContext, () => {});

    expect(dynamoMock.commandCalls(PutItemCommand)).toHaveLength(0);
    expect(mockAddMetric).toHaveBeenCalledWith("MalformedPayload", "Count", 1);
  });

  it("should skip messages with missing session_id", async () => {
    const event = createSQSEvent([
      createSQSRecord({ results: [], collection: "test", timestamp: 0 }),
    ]);
    await handler(event, mockContext, () => {});

    expect(dynamoMock.commandCalls(PutItemCommand)).toHaveLength(0);
    expect(mockAddMetric).toHaveBeenCalledWith("MissingSessionId", "Count", 1);
  });

  it("should process multiple records in a batch", async () => {
    const msg2 = { ...validMessage, session_id: "session-456" };
    const event = createSQSEvent([
      createSQSRecord(validMessage, "msg-1"),
      createSQSRecord(msg2, "msg-2"),
    ]);
    await handler(event, mockContext, () => {});

    expect(dynamoMock.commandCalls(PutItemCommand)).toHaveLength(2);
  });

  it("should emit VectorResultsWritten and VectorResultCount metrics", async () => {
    const event = createSQSEvent([createSQSRecord(validMessage)]);
    await handler(event, mockContext, () => {});

    expect(mockAddMetric).toHaveBeenCalledWith(
      "VectorResultsWritten",
      "Count",
      1,
    );
    expect(mockAddMetric).toHaveBeenCalledWith("VectorResultCount", "Count", 2);
  });
});
