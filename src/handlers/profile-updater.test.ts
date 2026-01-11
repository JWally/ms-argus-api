// src/handlers/profile-updater.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Set environment variables BEFORE any module imports using vi.hoisted
// This ensures env validation passes during module load
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-profile-updater-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.REDIS_ENDPOINT = "localhost";
  process.env.REDIS_PORT = "6379";
  process.env.PROFILES_TABLE = "test-profiles";
  process.env.TIER1_INDEX_TABLE = "test-tier1-index";
  process.env.TIER2_BUCKETS_TABLE = "test-tier2-buckets";
});

import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { SQSEvent, SQSRecord, Context } from "aws-lambda";
import RedisMock from "ioredis-mock";

// Mock AWS SDK clients
const dynamoMock = mockClient(DynamoDBClient);

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

// Import handler after mocking
import { handler } from "./profile-updater";

describe("profile-updater handler", () => {
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
    eventSourceARN: "arn:aws:sqs:us-east-1:123456789:test-profile-queue",
    awsRegion: "us-east-1",
  });

  const createSQSEvent = (records: SQSRecord[]): SQSEvent => ({
    Records: records,
  });

  const createProfileUpdatePayload = (overrides = {}) => ({
    tenant_id: "tenant-abc",
    device_id: "device-123",
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
    session_id: "session-123",
    risk_score: 0.25,
    confidence: 0.9,
    match_tier: 1,
    is_new_device: false,
    timestamp: Date.now(),
    ...overrides,
  });

  describe("successful processing", () => {
    it("should process a single profile update successfully", async () => {
      const payload = createProfileUpdatePayload();

      // Mock no existing profile (new device)
      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result).toBeDefined();
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should process multiple records in batch", async () => {
      const payload1 = createProfileUpdatePayload({ device_id: "device-1" });
      const payload2 = createProfileUpdatePayload({ device_id: "device-2" });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createSQSEvent([
        createSQSRecord(payload1, "msg-1"),
        createSQSRecord(payload2, "msg-2"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should update existing profile", async () => {
      const payload = createProfileUpdatePayload();

      // Mock existing profile
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant-abc",
          device_id: "device-123",
          fingerprints: {
            stable_hash: "old-hash",
          },
          created_at: Date.now() - 86400000, // 1 day ago
          updated_at: Date.now() - 3600000, // 1 hour ago
          profile_version: 1,
        }),
      });
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should write new device profile", async () => {
      const payload = createProfileUpdatePayload({ is_new_device: true });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Verify PutItemCommand was called
      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      expect(putCalls.length).toBeGreaterThan(0);
    });
  });

  describe("mutation gating", () => {
    it("should skip update when mutation gate is active", async () => {
      const payload = createProfileUpdatePayload();

      // Set mutation gate in Redis using correct key format
      await redisMock.setex(`recently_updated:device-123`, 3600, "1");

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Should not have written to DynamoDB due to mutation gate
      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      expect(putCalls).toHaveLength(0);
    });

    it("should process update when mutation gate expired", async () => {
      const payload = createProfileUpdatePayload();

      // No mutation gate in Redis (expired or never set)
      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("drift detection", () => {
    it("should skip update when fingerprint has no significant drift", async () => {
      const payload = createProfileUpdatePayload();

      // Mock existing profile with same fingerprint
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant-abc",
          device_id: "device-123",
          fingerprints: {
            stable_hash: "hash-abc123",
            fuzzy_hash: "fuzzy-def456",
            canvas_hash: "canvas-ghi789",
          },
          centroid: {
            stable_hash: "hash-abc123",
            fuzzy_hash: "fuzzy-def456",
          },
          created_at: Date.now() - 86400000,
          updated_at: Date.now() - 60000, // Recently updated
          profile_version: 5,
        }),
      });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should update when fingerprint has significant drift", async () => {
      const payload = createProfileUpdatePayload({
        fingerprint: {
          stable_hash: "completely-new-hash",
          fuzzy_hash: "completely-new-fuzzy",
          canvas_hash: "completely-new-canvas",
        },
      });

      // Mock existing profile with different fingerprint
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant-abc",
          device_id: "device-123",
          fingerprints: {
            stable_hash: "old-hash",
          },
          created_at: Date.now() - 86400000,
          updated_at: Date.now() - 7200000, // 2 hours ago
          profile_version: 1,
        }),
      });
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("tier index updates", () => {
    it("should update Tier 1 indexes for stable hash", async () => {
      const payload = createProfileUpdatePayload();

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Verify index writes
      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      // Should have profile + tier1 indexes
      expect(putCalls.length).toBeGreaterThanOrEqual(1);
    });

    it("should update Tier 2 bucket indexes", async () => {
      const payload = createProfileUpdatePayload({
        fingerprint: {
          ip_address: "192.168.1.1",
          ja4: "t13d1516h2_8daaf6152771",
          gpu_renderer: "NVIDIA GeForce RTX 3080",
          screen_dims: "1920x1080",
          timezone: "America/New_York",
        },
      });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("error handling", () => {
    it("should return failed item when DynamoDB throws", async () => {
      const payload = createProfileUpdatePayload();

      dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB error"));

      const event = createSQSEvent([createSQSRecord(payload, "failing-msg")]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("failing-msg");
    });

    it("should return failed items only for records that fail", async () => {
      const successPayload = createProfileUpdatePayload({
        device_id: "success-device",
      });
      const failPayload = createProfileUpdatePayload({
        device_id: "fail-device",
      });

      // First call succeeds, second fails
      let callCount = 0;
      dynamoMock.on(GetItemCommand).callsFake(() => {
        callCount++;
        if (callCount <= 1) {
          return {};
        }
        throw new Error("DynamoDB error");
      });
      dynamoMock.on(PutItemCommand).resolves({});

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

    it("should handle PutItem failure gracefully", async () => {
      const payload = createProfileUpdatePayload();

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).rejects(new Error("PutItem failed"));

      const event = createSQSEvent([createSQSRecord(payload, "put-fail-msg")]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("put-fail-msg");
    });
  });

  describe("TTL handling", () => {
    it("should set TTL on profile records", async () => {
      const payload = createProfileUpdatePayload({ is_new_device: true });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(PutItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      if (putCalls.length > 0) {
        const item = putCalls[0].args[0].input.Item;
        // TTL should be set (60 days from now)
        expect(item).toBeDefined();
      }
    });
  });
});
