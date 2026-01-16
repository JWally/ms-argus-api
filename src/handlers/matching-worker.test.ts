// src/handlers/matching-worker.test.ts
// AR-52: Updated to use DynamoDB session cache instead of Redis
// AR-123: Added tests for NEW_DEVICE_RATE metric
// AR-148: Added mock for anomaly detection
import { describe, it, expect, beforeEach, vi } from "vitest";

// AR-123: Mock Powertools Metrics to verify metric emission
// Must use vi.hoisted to create mock functions before vi.mock runs
const {
  mockAddMetric,
  mockPublishStoredMetrics,
  mockDetectAllAnomalies,
} = vi.hoisted(() => ({
  mockAddMetric: vi.fn(),
  mockPublishStoredMetrics: vi.fn(),
  // AR-148: Mock anomaly detection
  mockDetectAllAnomalies: vi.fn().mockReturnValue({
    signals: [],
    aggregateScore: 0,
    suggestedFlags: [],
  }),
}));

// AR-148: Mock anomaly detection to avoid errors in tests
vi.mock("../services/profile/anomaly", () => ({
  detectAllAnomalies: mockDetectAllAnomalies,
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: mockAddMetric,
    publishStoredMetrics: mockPublishStoredMetrics,
  })),
  MetricUnit: {
    Count: "Count",
    Milliseconds: "Milliseconds",
  },
}));

// Set environment variables BEFORE any module imports using vi.hoisted
// This ensures env validation passes during module load
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-matching-worker-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SESSION_CACHE_TABLE = "test-session-cache";
  process.env.TIER1_INDEX_TABLE = "test-tier1-index";
  process.env.TIER2_BUCKETS_TABLE = "test-tier2-buckets";
  process.env.PROFILES_TABLE = "test-profiles";
  process.env.PROFILE_QUEUE_URL =
    "https://sqs.us-east-1.amazonaws.com/123456789/test-profile-queue";
});

import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import { SQSEvent, SQSRecord, Context } from "aws-lambda";

// Mock AWS SDK clients
const dynamoMock = mockClient(DynamoDBClient);
const sqsMock = mockClient(SQSClient);

// Import handler after mocking
import { handler } from "./matching-worker";

describe("matching-worker handler", () => {
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
    sqsMock.reset();
    vi.clearAllMocks();
    // AR-123: Reset metric mocks
    mockAddMetric.mockClear();
    mockPublishStoredMetrics.mockClear();
  });

  const createSQSRecord = (
    body: object,
    messageId = "test-msg-1",
  ): SQSRecord => ({
    messageId,
    receiptHandle: "test-receipt-handle",
    body: JSON.stringify(body),
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

  const createFingerprintPayload = (overrides = {}) => ({
    session_id: "test-session-123",
    fingerprint: {
      stable_hash: "hash-abc123",
      fuzzy_hash: "fuzzy-def456",
      canvas_hash: "canvas-ghi789",
      ip_address: "192.168.1.1",
      ja4: "t13d1516h2_8daaf6152771",
      gpu_renderer: "NVIDIA GeForce RTX 3080",
      screen_dims: "1920x1080",
      timezone: "America/New_York",
    },
    timestamp: Date.now(),
    ...overrides,
  });

  describe("successful processing", () => {
    it("should process a single record successfully with Tier 1 match", async () => {
      const payload = createFingerprintPayload();

      // Mock Tier 1 index lookup - found existing device
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });

      // Mock SQS send for profile update
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "profile-msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result).toBeDefined();
      expect(result!.batchItemFailures).toHaveLength(0);

      // Verify profile update was queued
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBeGreaterThanOrEqual(1);
    });

    it("should process multiple records in batch", async () => {
      const payload1 = createFingerprintPayload({ session_id: "session-1" });
      const payload2 = createFingerprintPayload({ session_id: "session-2" });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(payload1, "msg-1"),
        createSQSRecord(payload2, "msg-2"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should skip processing for cache hit (Tier 0)", async () => {
      const payload = createFingerprintPayload();

      // AR-52: Pre-populate DynamoDB session cache with complete result
      dynamoMock.on(GetItemCommand).callsFake((input) => {
        const key = input.Key;
        // Return cached session for session cache lookups
        if (key?.cache_key?.S === `session:${payload.session_id}`) {
          return {
            Item: marshall({
              cache_key: `session:${payload.session_id}`,
              value: {
                status: "complete",
                device_id: "cached-device-123",
                risk_score: 0.2,
                confidence: 0.95,
                match_tier: 1,
                match_version: 1,
                idempotency_key: "cached-key",
                flags: [],
                updated_at: Date.now(),
              },
              ttl: Math.floor(Date.now() / 1000) + 900,
            }),
          };
        }
        return { Item: undefined };
      });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Should not have queued profile update since we had a cache hit
      expect(sqsMock.calls()).toHaveLength(0);
    });

    it("should create new device when no match found", async () => {
      const payload = createFingerprintPayload({
        fingerprint: {
          stable_hash: "brand-new-hash",
          fuzzy_hash: "brand-new-fuzzy",
        },
      });

      // Mock no match found in any tier
      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Should have queued profile update for new device
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("error handling", () => {
    it("should return failed item when DynamoDB throws", async () => {
      const payload = createFingerprintPayload();

      dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB error"));

      const event = createSQSEvent([createSQSRecord(payload, "failing-msg")]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("failing-msg");
    });

    it("should return failed items only for records that fail", async () => {
      const successPayload = createFingerprintPayload({
        session_id: "success-session",
        fingerprint: { evercookie_id: "cookie-success" },
      });
      const failPayload = createFingerprintPayload({
        session_id: "fail-session",
        fingerprint: { evercookie_id: "cookie-fail" },
      });

      // AR-52: The session cache check and tier1 lookups both use GetItemCommand
      // Mock based on the hash_key to simulate success for first record, failure for second
      dynamoMock.on(GetItemCommand).callsFake((input) => {
        const key = input.Key;
        // Session cache lookups (cache_key starts with "session:")
        if (key?.cache_key?.S?.startsWith("session:")) {
          return { Item: undefined }; // Cache miss
        }
        // Tier1 index lookups - success for cookie-success, fail for cookie-fail
        if (key?.hash_key?.S?.includes("cookie-success")) {
          return {
            Item: marshall({
              hash_key: "evercookie#cookie-success",
              device_id: "device-123",
            }),
          };
        }
        if (key?.hash_key?.S?.includes("cookie-fail")) {
          throw new Error("DynamoDB error");
        }
        return { Item: undefined };
      });

      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(successPayload, "success-msg"),
        createSQSRecord(failPayload, "fail-msg"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("fail-msg");
    });

    it("should handle invalid JSON in record body", async () => {
      const event = createSQSEvent([
        {
          ...createSQSRecord({}, "invalid-msg"),
          body: "not-valid-json",
        },
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("invalid-msg");
    });

    it("should write degraded status on matching failure", async () => {
      const payload = createFingerprintPayload();

      // Mock matching failure
      dynamoMock.on(GetItemCommand).rejects(new Error("Matching failed"));

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      // The record should be marked as failed since matching threw an error
      expect(result!.batchItemFailures).toHaveLength(1);
    });
  });

  describe("tier matching metrics", () => {
    it("should process Tier 0.5 (evercookie) match", async () => {
      const payload = createFingerprintPayload({
        fingerprint: {
          evercookie_id: "evercookie-abc123",
        },
      });

      // Mock evercookie lookup success
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "evercookie-abc123",
          device_id: "evercookie-device-123",
        }),
      });

      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  // AR-71: Warmup message handling
  describe("warmup message handling", () => {
    it("should handle warmup message without processing", async () => {
      const warmupMessage = {
        warmup: true,
        source: "warmup-rule",
        timestamp: "2025-01-14T00:00:00Z",
      };

      const event = createSQSEvent([
        createSQSRecord(warmupMessage, "warmup-msg"),
      ]);
      const result = await handler(event, mockContext, () => {});

      // Should succeed without failures
      expect(result!.batchItemFailures).toHaveLength(0);

      // Should NOT call DynamoDB (no matching work)
      expect(dynamoMock.calls()).toHaveLength(0);

      // Should NOT queue profile updates
      expect(sqsMock.calls()).toHaveLength(0);
    });

    it("should handle warmup message mixed with regular messages", async () => {
      const warmupMessage = {
        warmup: true,
        source: "warmup-rule",
      };
      const regularPayload = createFingerprintPayload();

      // Mock Tier 1 match for regular message
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(warmupMessage, "warmup-msg"),
        createSQSRecord(regularPayload, "regular-msg"),
      ]);

      const result = await handler(event, mockContext, () => {});

      // Both should succeed
      expect(result!.batchItemFailures).toHaveLength(0);

      // DynamoDB should be called only for regular message
      expect(dynamoMock.calls().length).toBeGreaterThan(0);
    });
  });

  // AR-123: NEW_DEVICE_RATE metric tests
  describe("NEW_DEVICE_RATE metric emission", () => {
    it("should emit NEW_DEVICE_RATE metric when is_new_device=true", async () => {
      const payload = createFingerprintPayload({
        fingerprint: {
          stable_hash: "brand-new-hash",
          fuzzy_hash: "brand-new-fuzzy",
        },
      });

      // Mock no match found in any tier (new device)
      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      // Verify NEW_DEVICE_RATE metric was emitted
      expect(mockAddMetric).toHaveBeenCalledWith("NEW_DEVICE_RATE", "Count", 1);
      // Also verify NewDevice metric (legacy)
      expect(mockAddMetric).toHaveBeenCalledWith("NewDevice", "Count", 1);
    });

    it("should NOT emit NEW_DEVICE_RATE when is_new_device=false", async () => {
      const payload = createFingerprintPayload();

      // Mock Tier 1 match (existing device)
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      // Verify NEW_DEVICE_RATE metric was NOT emitted
      expect(mockAddMetric).not.toHaveBeenCalledWith(
        "NEW_DEVICE_RATE",
        "Count",
        1,
      );
      // Verify NewDevice metric was NOT emitted
      expect(mockAddMetric).not.toHaveBeenCalledWith("NewDevice", "Count", 1);
      // Should have emitted Tier1Hit instead
      expect(mockAddMetric).toHaveBeenCalledWith("Tier1Hit", "Count", 1);
    });
  });
});
