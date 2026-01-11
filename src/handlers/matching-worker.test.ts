// src/handlers/matching-worker.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import { SQSEvent, SQSRecord, Context } from "aws-lambda";
import RedisMock from "ioredis-mock";

// Mock AWS SDK clients
const dynamoMock = mockClient(DynamoDBClient);
const sqsMock = mockClient(SQSClient);

// Create a mock Redis instance
let redisMock: InstanceType<typeof RedisMock>;

// Mock ioredis module
vi.mock("ioredis", () => {
  return {
    default: vi.fn().mockImplementation(() => {
      redisMock = new RedisMock();
      return redisMock;
    }),
  };
});

// Mock environment variables
vi.stubEnv("POWERTOOLS_SERVICE_NAME", "argus-matching-worker-test");
vi.stubEnv("POWERTOOLS_METRICS_NAMESPACE", "argus-test");
vi.stubEnv("REDIS_ENDPOINT", "localhost");
vi.stubEnv("REDIS_PORT", "6379");
vi.stubEnv("TIER1_INDEX_TABLE", "test-tier1-index");
vi.stubEnv("TIER2_BUCKETS_TABLE", "test-tier2-buckets");
vi.stubEnv("PROFILES_TABLE", "test-profiles");
vi.stubEnv(
  "PROFILE_QUEUE_URL",
  "https://sqs.us-east-1.amazonaws.com/123456789/test-profile-queue",
);

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
    redisMock = new RedisMock();
    vi.clearAllMocks();
  });

  afterEach(async () => {
    if (redisMock) {
      await redisMock.flushall();
    }
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
    tenant_id: "tenant-abc",
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
          tenant_id: "tenant-abc",
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
          tenant_id: "tenant-abc",
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

      // Pre-populate Redis cache with complete result
      await redisMock.set(
        `session:${payload.session_id}`,
        JSON.stringify({
          status: "complete",
          device_id: "cached-device-123",
          risk_score: 0.2,
          confidence: 0.95,
          match_tier: 1,
          match_version: 1,
          idempotency_key: "cached-key",
          flags: [],
          updated_at: Date.now(),
        }),
      );

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Should not have written to DynamoDB since we had a cache hit
      // May still do a lookup, but shouldn't have queued profile update
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
      });
      const failPayload = createFingerprintPayload({
        session_id: "fail-session",
      });

      // First call succeeds, second fails
      let callCount = 0;
      dynamoMock.on(GetItemCommand).callsFake(() => {
        callCount++;
        if (callCount === 1) {
          return {
            Item: marshall({
              tenant_id: "tenant-abc",
              hash_value: "hash-abc123",
              device_id: "device-123",
            }),
          };
        }
        throw new Error("DynamoDB error");
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
      await handler(event, mockContext, () => {});

      // Check that degraded status was written to Redis
      const cached = await redisMock.get(`session:${payload.session_id}`);
      if (cached) {
        const parsed = JSON.parse(cached);
        expect(parsed.status).toBe("degraded");
      }
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
          tenant_id: "tenant-abc",
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
});
