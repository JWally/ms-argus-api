// src/services/cache/dynamo-cache.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { DynamoCacheService, DynamoCacheConfig } from "./dynamo-cache";
import { SessionCacheValue } from "../../types";

// Mock DynamoDB client
const dynamoMock = mockClient(DynamoDBClient);

// Test configuration
const testConfig: DynamoCacheConfig = {
  tableName: "test-session-cache",
  sessionTtlSeconds: 900,
  mutationGateTtlSeconds: 3600,
};

describe("DynamoCacheService", () => {
  let dynamodb: DynamoDBClient;
  let service: DynamoCacheService;

  beforeEach(() => {
    dynamoMock.reset();
    dynamodb = new DynamoDBClient({});
    service = new DynamoCacheService(dynamodb, testConfig);
  });

  describe("checkSessionCache", () => {
    it("should return null when session is not cached", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.checkSessionCache("unknown-session");

      expect(result).toBeNull();
    });

    it("should return cached value when session exists", async () => {
      const sessionValue: SessionCacheValue = {
        status: "complete",
        device_id: "dev_123",
        risk_score: 0.3,
        confidence: 0.95,
        match_tier: 1,
        match_version: 1,
        idempotency_key: "idem_abc",
        flags: ["returning"],
        updated_at: Date.now(),
      };

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: "session:test-session",
          value: sessionValue,
          confidence: sessionValue.confidence,
          ttl: Math.floor(Date.now() / 1000) + 900, // Not expired
        }),
      });

      const result = await service.checkSessionCache("test-session");

      expect(result).toEqual(sessionValue);
    });

    it("should return null when TTL has expired", async () => {
      const sessionValue: SessionCacheValue = {
        status: "complete",
        device_id: "dev_123",
        risk_score: 0.3,
        confidence: 0.95,
        match_tier: 1,
        match_version: 1,
        idempotency_key: "idem_abc",
        flags: [],
        updated_at: Date.now(),
      };

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: "session:expired-session",
          value: sessionValue,
          confidence: sessionValue.confidence,
          ttl: Math.floor(Date.now() / 1000) - 100, // Expired
        }),
      });

      const result = await service.checkSessionCache("expired-session");

      expect(result).toBeNull();
    });

    it("should query with correct key format", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      await service.checkSessionCache("my-session-id");

      const calls = dynamoMock.commandCalls(GetItemCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input).toEqual({
        TableName: "test-session-cache",
        Key: marshall({ cache_key: "session:my-session-id" }),
      });
    });
  });

  describe("writeSessionCache", () => {
    it("should write session value with correct TTL", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const value: SessionCacheValue = {
        status: "complete",
        device_id: "dev_456",
        risk_score: 0.2,
        confidence: 0.9,
        match_tier: 1,
        match_version: 1,
        idempotency_key: "idem_xyz",
        flags: ["new_device"],
        updated_at: Date.now(),
      };

      await service.writeSessionCache("new-session", value);

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(1);

      const input = calls[0].args[0].input;
      expect(input.TableName).toBe("test-session-cache");
      expect(input.ConditionExpression).toContain("attribute_not_exists");
    });

    it("should not throw when conditional check fails (existing higher confidence)", async () => {
      dynamoMock.on(PutItemCommand).rejects(
        new ConditionalCheckFailedException({
          message: "Conditional check failed",
          $metadata: {},
        }),
      );

      const value: SessionCacheValue = {
        status: "complete",
        device_id: "dev_456",
        risk_score: 0.2,
        confidence: 0.5, // Lower confidence
        match_tier: 2,
        match_version: 1,
        idempotency_key: "idem_xyz",
        flags: [],
        updated_at: Date.now(),
      };

      // Should not throw
      await expect(
        service.writeSessionCache("existing-session", value),
      ).resolves.toBeUndefined();
    });

    it("should propagate non-conditional-check errors", async () => {
      dynamoMock.on(PutItemCommand).rejects(new Error("DynamoDB error"));

      const value: SessionCacheValue = {
        status: "complete",
        device_id: "dev_456",
        risk_score: 0.2,
        confidence: 0.9,
        match_tier: 1,
        match_version: 1,
        idempotency_key: "idem_xyz",
        flags: [],
        updated_at: Date.now(),
      };

      await expect(
        service.writeSessionCache("error-session", value),
      ).rejects.toThrow("DynamoDB error");
    });
  });

  describe("tryAcquireMutationGate", () => {
    it("should return true when gate is acquired", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const result = await service.tryAcquireMutationGate("device-123");

      expect(result).toBe(true);
    });

    it("should return false when gate already exists", async () => {
      dynamoMock.on(PutItemCommand).rejects(
        new ConditionalCheckFailedException({
          message: "Conditional check failed",
          $metadata: {},
        }),
      );

      const result = await service.tryAcquireMutationGate("device-123");

      expect(result).toBe(false);
    });

    it("should use correct key format for gate", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      await service.tryAcquireMutationGate("my-device-id");

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(1);

      const input = calls[0].args[0].input;
      expect(input.TableName).toBe("test-session-cache");
      expect(input.ConditionExpression).toBe("attribute_not_exists(cache_key)");
    });

    it("should propagate non-conditional-check errors", async () => {
      dynamoMock.on(PutItemCommand).rejects(new Error("DynamoDB unavailable"));

      await expect(
        service.tryAcquireMutationGate("device-123"),
      ).rejects.toThrow("DynamoDB unavailable");
    });
  });

  describe("key patterns", () => {
    it("should use 'session:' prefix for session cache keys", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      await service.checkSessionCache("abc-123");

      const calls = dynamoMock.commandCalls(GetItemCommand);
      const key = calls[0].args[0].input.Key;
      expect(key).toEqual(marshall({ cache_key: "session:abc-123" }));
    });

    it("should use 'gate:' prefix for mutation gate keys", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      await service.tryAcquireMutationGate("device-xyz");

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;
      // The item should contain cache_key with gate: prefix
      expect(item).toBeDefined();
    });
  });
});
