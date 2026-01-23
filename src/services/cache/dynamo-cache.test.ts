import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { DynamoCacheService } from "./dynamo-cache";

const dynamoMock = mockClient(DynamoDBClient);

describe("DynamoCacheService", () => {
  let service: DynamoCacheService;

  beforeEach(() => {
    dynamoMock.reset();
    service = new DynamoCacheService(new DynamoDBClient({}), {
      tableName: "test-cache",
      sessionTtlSeconds: 900,
      mutationGateTtlSeconds: 30,
    });
  });

  describe("checkSessionCache", () => {
    it("should return null when item not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.checkSessionCache("session-123");
      expect(result).toBeNull();
    });

    it("should return cached value when found and not expired", async () => {
      const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: "session:session-123",
          value: { status: "complete", device_id: "dev_1", confidence: 0.95 },
          ttl: futureTimestamp,
        }),
      });

      const result = await service.checkSessionCache("session-123");
      expect(result).toEqual({
        status: "complete",
        device_id: "dev_1",
        confidence: 0.95,
      });
    });

    it("should return null when TTL is expired", async () => {
      const pastTimestamp = Math.floor(Date.now() / 1000) - 100;
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: "session:session-123",
          value: { status: "complete", device_id: "dev_1", confidence: 0.95 },
          ttl: pastTimestamp,
        }),
      });

      const result = await service.checkSessionCache("session-123");
      expect(result).toBeNull();
    });

    it("should return value when no TTL field present", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: "session:session-123",
          value: { status: "complete", device_id: "dev_1", confidence: 0.9 },
        }),
      });

      const result = await service.checkSessionCache("session-123");
      expect(result).toEqual({
        status: "complete",
        device_id: "dev_1",
        confidence: 0.9,
      });
    });
  });

  describe("writeSessionCache", () => {
    it("should return true on successful write", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const result = await service.writeSessionCache("session-123", {
        status: "complete",
        device_id: "dev_1",
        risk_score: 0.3,
        confidence: 0.95,
        match_tier: 1,
        match_version: Date.now(),
        idempotency_key: "key-1",
        flags: [],
        evidence_codes: [],
        updated_at: Date.now(),
      });

      expect(result).toBe(true);
    });

    it("should return false when ConditionalCheckFailed (higher confidence exists)", async () => {
      dynamoMock.on(PutItemCommand).rejects(
        new ConditionalCheckFailedException({
          message: "Condition not met",
          $metadata: {},
        }),
      );

      const result = await service.writeSessionCache("session-123", {
        status: "complete",
        device_id: "dev_1",
        risk_score: 0.3,
        confidence: 0.5,
        match_tier: 2,
        match_version: Date.now(),
        idempotency_key: "key-2",
        flags: [],
        evidence_codes: [],
        updated_at: Date.now(),
      });

      expect(result).toBe(false);
    });

    it("should rethrow non-ConditionalCheckFailed errors", async () => {
      dynamoMock.on(PutItemCommand).rejects(new Error("Network error"));

      await expect(
        service.writeSessionCache("session-123", {
          status: "complete",
          device_id: "dev_1",
          risk_score: 0.3,
          confidence: 0.95,
          match_tier: 1,
          match_version: Date.now(),
          idempotency_key: "key-3",
          flags: [],
          evidence_codes: [],
          updated_at: Date.now(),
        }),
      ).rejects.toThrow("Network error");
    });
  });

  describe("tryAcquireMutationGate", () => {
    it("should return true when gate acquired successfully", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const result = await service.tryAcquireMutationGate("device-abc");
      expect(result).toBe(true);
    });

    it("should return false when gate already exists", async () => {
      dynamoMock.on(PutItemCommand).rejects(
        new ConditionalCheckFailedException({
          message: "Condition not met",
          $metadata: {},
        }),
      );

      const result = await service.tryAcquireMutationGate("device-abc");
      expect(result).toBe(false);
    });

    it("should rethrow non-ConditionalCheckFailed errors", async () => {
      dynamoMock.on(PutItemCommand).rejects(new Error("Throttled"));

      await expect(
        service.tryAcquireMutationGate("device-abc"),
      ).rejects.toThrow("Throttled");
    });
  });
});
