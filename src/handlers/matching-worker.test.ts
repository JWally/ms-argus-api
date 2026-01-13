// src/handlers/matching-worker.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";

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
  PutItemCommand,
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

      // Mock session cache lookup (no cache hit)
      dynamoMock
        .on(GetItemCommand, {
          TableName: "test-session-cache",
        })
        .resolves({ Item: undefined });

      // Mock Tier 1 index lookup - found existing device
      dynamoMock
        .on(GetItemCommand, {
          TableName: "test-tier1-index",
        })
        .resolves({
          Item: marshall({
            tenant_id: "tenant-abc",
            hash_key: "stable#hash-abc123",
            device_id: "existing-device-123",
          }),
        });

      // Mock session cache write
      dynamoMock.on(PutItemCommand).resolves({});

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

      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .resolves({
          Item: marshall({
            tenant_id: "tenant-abc",
            hash_key: "stable#hash-abc123",
            device_id: "device-123",
          }),
        });

      dynamoMock.on(PutItemCommand).resolves({});
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

      // Mock session cache hit
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({
          Item: marshall({
            cache_key: `session:${payload.session_id}`,
            value: {
              status: "complete",
              device_id: "cached-device-123",
              risk_score: 0.2,
              confidence: 0.95,
              match_tier: 1,
              match_version: Date.now(),
              idempotency_key: "cached-key",
              flags: [],
              updated_at: Date.now(),
            },
            confidence: 0.95,
            ttl: Math.floor(Date.now() / 1000) + 900, // Valid TTL
          }),
        });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should create new device when no match found", async () => {
      const payload = createFingerprintPayload({
        fingerprint: {
          stable_hash: "brand-new-hash",
          fuzzy_hash: "brand-new-fuzzy",
        },
      });

      // Mock no cache hit
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      // Mock no match found in any tier
      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .resolves({});
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      dynamoMock.on(PutItemCommand).resolves({});
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

      // Mock no cache hit
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      // Mock DynamoDB error on tier1 lookup
      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .rejects(new Error("DynamoDB error"));

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

      // Mock no cache hits
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      // First tier1 call succeeds, second fails
      let tier1CallCount = 0;
      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .callsFake(() => {
          tier1CallCount++;
          if (tier1CallCount === 1) {
            return {
              Item: marshall({
                tenant_id: "tenant-abc",
                hash_key: "stable#hash-abc123",
                device_id: "device-123",
              }),
            };
          }
          throw new Error("DynamoDB error");
        });

      dynamoMock.on(PutItemCommand).resolves({});
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

      // Mock no cache hit
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      // Mock matching failure
      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .rejects(new Error("Matching failed"));

      // Mock cache write for degraded status
      dynamoMock.on(PutItemCommand).resolves({});

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      // Verify degraded status was written to DynamoDB cache
      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      const cacheWrite = putCalls.find(
        (call) => call.args[0].input.TableName === "test-session-cache",
      );
      expect(cacheWrite).toBeDefined();
    });
  });

  describe("tier matching metrics", () => {
    it("should process Tier 0.5 (evercookie) match", async () => {
      const payload = createFingerprintPayload({
        fingerprint: {
          evercookie_id: "evercookie-abc123",
        },
      });

      // Mock no cache hit
      dynamoMock
        .on(GetItemCommand, { TableName: "test-session-cache" })
        .resolves({ Item: undefined });

      // Mock evercookie lookup success
      dynamoMock
        .on(GetItemCommand, { TableName: "test-tier1-index" })
        .resolves({
          Item: marshall({
            tenant_id: "tenant-abc",
            hash_key: "evercookie#evercookie-abc123",
            device_id: "evercookie-device-123",
          }),
        });

      dynamoMock.on(PutItemCommand).resolves({});
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });
});
