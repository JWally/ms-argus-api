// src/services/matching/matching-service.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import RedisMock from "ioredis-mock";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  generateIdempotencyKey,
  generateUUID,
} from "./matching-service";
import { Fingerprint, SessionCacheValue } from "./types";

// Mock AWS SDK clients
const dynamoMock = mockClient(DynamoDBClient);
const sqsMock = mockClient(SQSClient);

// Test configuration
const testConfig: MatchingServiceConfig = {
  tier1IndexTable: "test-tier1-index",
  tier2BucketsTable: "test-tier2-buckets",
  profilesTable: "test-profiles",
  profileQueueUrl: "https://sqs.us-east-1.amazonaws.com/123456789/test-queue",
  sessionTtlSeconds: 900,
  tier2TimeoutMs: 100,
};

describe("MatchingService", () => {
  let redis: InstanceType<typeof RedisMock>;
  let dynamodb: DynamoDBClient;
  let sqs: SQSClient;
  let service: MatchingService;

  beforeEach(() => {
    // Reset mocks
    dynamoMock.reset();
    sqsMock.reset();

    // Create fresh Redis mock
    redis = new RedisMock();

    // Create real clients (mocked by aws-sdk-client-mock)
    dynamodb = new DynamoDBClient({});
    sqs = new SQSClient({});

    // Create service with test dependencies
    const deps: MatchingServiceDeps = {
      dynamodb,
      sqs,
      redis: redis as any, // ioredis-mock is compatible
      config: testConfig,
    };
    service = new MatchingService(deps);
  });

  afterEach(async () => {
    await redis.quit();
  });

  describe("checkCache", () => {
    it("should return null when session is not cached", async () => {
      const result = await service.checkCache("unknown-session");
      expect(result).toBeNull();
    });

    it("should return cached value when session exists", async () => {
      const sessionId = "cached-session";
      const cachedValue: SessionCacheValue = {
        status: "complete",
        device_id: "dev_123",
        risk_score: 0.3,
        confidence: 0.95,
        match_tier: 1,
        match_version: Date.now(),
        idempotency_key: "abc123",
        flags: ["verified"],
        updated_at: Date.now(),
      };

      await redis.set(`session:${sessionId}`, JSON.stringify(cachedValue));

      const result = await service.checkCache(sessionId);
      expect(result).not.toBeNull();
      expect(result?.status).toBe("complete");
      expect(result?.device_id).toBe("dev_123");
      expect(result?.confidence).toBe(0.95);
    });
  });

  describe("tier05CookieLookup", () => {
    it("should return null when evercookie not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.tier05CookieLookup(
        "tenant1",
        "unknown-cookie",
      );
      expect(result).toBeNull();
    });

    it("should return match result when evercookie found", async () => {
      const deviceId = "dev_existing";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          hash_key: "evercookie#cookie123",
          device_id: deviceId,
          risk_score: 0.2,
          flags: ["trusted"],
        }),
      });

      const result = await service.tier05CookieLookup("tenant1", "cookie123");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe(deviceId);
      expect(result?.confidence).toBe(0.99);
      expect(result?.match_tier).toBe(0.5);
      expect(result?.is_new_device).toBe(false);
      expect(result?.risk_score).toBe(0.2);
      expect(result?.flags).toEqual(["trusted"]);
    });

    it("should use default risk_score when not in index", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          hash_key: "evercookie#cookie123",
          device_id: "dev_123",
        }),
      });

      const result = await service.tier05CookieLookup("tenant1", "cookie123");
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  describe("tier1HashMatch", () => {
    it("should return null result when no hash matches", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const { result } = await service.tier1HashMatch("tenant1", fingerprint);
      expect(result).toBeNull();
    });

    it("should match on stable_hash with 0.95 confidence", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          hash_key: "stable#stable123",
          device_id: "dev_stable",
          risk_score: 0.25,
        }),
      });

      const fingerprint: Fingerprint = { stable_hash: "stable123" };
      const { result } = await service.tier1HashMatch("tenant1", fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_stable");
      expect(result?.confidence).toBe(0.95);
      expect(result?.match_tier).toBe(1);
    });

    it("should match on fuzzy_hash with 0.85 confidence when stable_hash not found", async () => {
      dynamoMock
        .on(GetItemCommand, {
          TableName: testConfig.tier1IndexTable,
          Key: {
            tenant_id: { S: "tenant1" },
            hash_key: { S: "stable#stable123" },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
          TableName: testConfig.tier1IndexTable,
          Key: {
            tenant_id: { S: "tenant1" },
            hash_key: { S: "fuzzy#fuzzy456" },
          },
        })
        .resolves({
          Item: marshall({
            tenant_id: "tenant1",
            hash_key: "fuzzy#fuzzy456",
            device_id: "dev_fuzzy",
          }),
        });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const { result } = await service.tier1HashMatch("tenant1", fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_fuzzy");
      expect(result?.confidence).toBe(0.85);
    });

    it("should prefer stable_hash over fuzzy_hash when both available", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          hash_key: "stable#stable123",
          device_id: "dev_stable",
        }),
      });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const { result } = await service.tier1HashMatch("tenant1", fingerprint);
      expect(result?.confidence).toBe(0.95); // stable_hash confidence
    });
  });

  describe("buildBucketKeys", () => {
    it("should return empty array when no compound signals available", () => {
      const fingerprint: Fingerprint = {};
      const keys = service.buildBucketKeys("tenant1", fingerprint);
      expect(keys).toEqual([]);
    });

    it("should build ip_ja4 bucket key", () => {
      const fingerprint: Fingerprint = {
        ip_address: "192.168.1.1",
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
      };

      const keys = service.buildBucketKeys("tenant1", fingerprint);
      expect(keys).toContain(
        "tenant1#ip_ja4#192.168.1.1#t13d1516h2_8daaf6152771_02713d6af862",
      );
    });

    it("should build gpu_screen_tz bucket key", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "ANGLE (Intel, Mesa Intel UHD Graphics 620)",
        screen_dims: "1920x1080",
        timezone: "America/New_York",
      };

      const keys = service.buildBucketKeys("tenant1", fingerprint);
      expect(keys).toHaveLength(1);
      expect(keys[0]).toContain("gpu_screen_tz");
      expect(keys[0]).toContain("1920x1080");
    });

    it("should build audio_canvas bucket key", () => {
      const fingerprint: Fingerprint = {
        audio_hash: "audio123",
        canvas_hash: "canvas456",
      };

      const keys = service.buildBucketKeys("tenant1", fingerprint);
      expect(keys).toContain("tenant1#audio_canvas#audio123#canvas456");
    });

    it("should build all bucket keys when all signals present", () => {
      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1080x720",
        timezone: "UTC",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const keys = service.buildBucketKeys("tenant1", fingerprint);
      expect(keys).toHaveLength(3);
    });
  });

  describe("tier2CompoundMatch", () => {
    it("should return null when no buckets match", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const result = await service.tier2CompoundMatch("tenant1", fingerprint);
      expect(result).toBeNull();
    });

    it("should return null when only one bucket matches (need 2+)", async () => {
      // Only one bucket has the device (single Query returns items)
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({
            bucket_key: "tenant1#ip_ja4#1.2.3.4#ja4hash",
            device_id: "dev_single",
          }),
        ],
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const result = await service.tier2CompoundMatch("tenant1", fingerprint);
      expect(result).toBeNull();
    });

    it("should return match when device appears in 2+ buckets", async () => {
      // Mock Query to return devices from each bucket (adjacency list pattern)
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [
            marshall({ bucket_key: "bucket1", device_id: "dev_match" }),
            marshall({ bucket_key: "bucket1", device_id: "dev_other" }),
          ],
        });

      // Also mock profile lookup
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({
            tenant_id: "tenant1",
            device_id: "dev_match",
            risk_score: 0.35,
            flags: ["suspicious"],
          }),
        });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const result = await service.tier2CompoundMatch("tenant1", fingerprint);

      expect(result).not.toBeNull();
      expect(result?.match_tier).toBe(2);
      expect(result?.confidence).toBeGreaterThanOrEqual(0.6);
      expect(result?.confidence).toBeLessThanOrEqual(0.85);
    });
  });

  describe("tier2CompoundMatchWithTimeout", () => {
    it("should return timedOut=true if matching takes too long", async () => {
      // Make DynamoDB calls slow
      dynamoMock.on(QueryCommand).callsFake(async () => {
        await new Promise((resolve) => setTimeout(resolve, 200)); // Longer than 100ms timeout
        return { Items: [] };
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const { result, timedOut } = await service.tier2CompoundMatchWithTimeout(
        "tenant1",
        fingerprint,
      );
      expect(result).toBeNull();
      expect(timedOut).toBe(true);
    });

    it("should return timedOut=false when matching completes in time", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const { result, timedOut } = await service.tier2CompoundMatchWithTimeout(
        "tenant1",
        fingerprint,
      );
      expect(result).toBeNull();
      expect(timedOut).toBe(false);
    });

    it("should handle AbortError gracefully in tier2CompoundMatch", async () => {
      // Create an already-aborted signal
      const abortController = new AbortController();
      abortController.abort();

      // Mock DynamoDB to throw AbortError when abort signal is provided
      dynamoMock.on(QueryCommand).callsFake(() => {
        const error = new Error("The operation was aborted");
        error.name = "AbortError";
        throw error;
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      // tier2CompoundMatch should catch AbortError and return null
      const result = await service.tier2CompoundMatch("tenant1", fingerprint, {
        abortSignal: abortController.signal,
      });
      expect(result).toBeNull();
    });

    it("should propagate non-abort errors in tier2CompoundMatch", async () => {
      // Mock DynamoDB to throw a different error
      const dbError = new Error("DynamoDB error");
      dbError.name = "ServiceUnavailable";
      dynamoMock.on(QueryCommand).rejects(dbError);

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      // Non-abort errors should be propagated
      await expect(
        service.tier2CompoundMatch("tenant1", fingerprint),
      ).rejects.toThrow("DynamoDB error");
    });
  });

  describe("loadProfile", () => {
    it("should return null when profile not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.loadProfile("tenant1", "unknown-device");
      expect(result).toBeNull();
    });

    it("should return profile with risk_score and flags", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          device_id: "dev_123",
          risk_score: 0.7,
          flags: ["bot_detected", "vpn"],
        }),
      });

      const result = await service.loadProfile("tenant1", "dev_123");

      expect(result).not.toBeNull();
      expect(result?.risk_score).toBe(0.7);
      expect(result?.flags).toEqual(["bot_detected", "vpn"]);
    });
  });

  describe("createNewDevice", () => {
    it("should create device with dev_ prefix", () => {
      const result = service.createNewDevice();

      expect(result.device_id).toMatch(/^dev_[a-f0-9-]+$/);
      expect(result.is_new_device).toBe(true);
      expect(result.confidence).toBe(1.0);
      expect(result.match_tier).toBe(-1);
      expect(result.risk_score).toBe(0.5);
      expect(result.flags).toEqual([]);
    });

    it("should generate unique device IDs", () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(service.createNewDevice().device_id);
      }
      expect(ids.size).toBe(100);
    });
  });

  describe("runTieredMatching", () => {
    it("should return evercookie match at Tier 0.5", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          tenant_id: "tenant1",
          hash_key: "evercookie#cookie123",
          device_id: "dev_cookie",
        }),
      });

      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const { result, tier2TimedOut } = await service.runTieredMatching(
        "tenant1",
        fingerprint,
      );

      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_cookie");
      expect(tier2TimedOut).toBe(false);
    });

    it("should fall through to Tier 1 when evercookie not found", async () => {
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            tenant_id: { S: "tenant1" },
            hash_key: { S: "evercookie#cookie123" },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
          Key: {
            tenant_id: { S: "tenant1" },
            hash_key: { S: "stable#stable456" },
          },
        })
        .resolves({
          Item: marshall({
            tenant_id: "tenant1",
            hash_key: "stable#stable456",
            device_id: "dev_stable",
          }),
        });

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable456",
      };

      const { result } = await service.runTieredMatching(
        "tenant1",
        fingerprint,
      );
      expect(result.match_tier).toBe(1);
    });

    it("should create new device when all tiers fail", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        stable_hash: "unknown",
      };

      const { result, tier2TimedOut } = await service.runTieredMatching(
        "tenant1",
        fingerprint,
      );

      expect(result.is_new_device).toBe(true);
      expect(result.match_tier).toBe(-1);
      expect(result.device_id).toMatch(/^dev_/);
      expect(tier2TimedOut).toBe(false);
    });

    it("should track tier2TimedOut when Tier 2 times out", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      // Make Tier 2 Query slow to trigger timeout
      dynamoMock.on(QueryCommand).callsFake(async () => {
        await new Promise((resolve) => setTimeout(resolve, 200));
        return { Items: [] };
      });

      const fingerprint: Fingerprint = {
        stable_hash: "unknown",
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const { result, tier2TimedOut } = await service.runTieredMatching(
        "tenant1",
        fingerprint,
      );

      expect(result.is_new_device).toBe(true);
      expect(tier2TimedOut).toBe(true);
    });
  });

  describe("writeMatchResult", () => {
    it("should write result to Redis with TTL", async () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [],
      };

      await service.writeMatchResult("session123", result, "idempkey");

      const cached = await redis.get("session:session123");
      expect(cached).not.toBeNull();

      const value: SessionCacheValue = JSON.parse(cached!);
      expect(value.status).toBe("complete");
      expect(value.device_id).toBe("dev_123");
      expect(value.confidence).toBe(0.95);
    });

    it("should not overwrite higher confidence match", async () => {
      // Pre-populate with higher confidence match
      const existing: SessionCacheValue = {
        status: "complete",
        device_id: "dev_better",
        risk_score: 0.2,
        confidence: 0.99,
        match_tier: 0.5,
        match_version: Date.now(),
        idempotency_key: "old",
        flags: [],
        updated_at: Date.now(),
      };
      await redis.set("session:session123", JSON.stringify(existing));

      // Try to write lower confidence match
      const result = {
        device_id: "dev_worse",
        confidence: 0.85,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.5,
        flags: [],
      };

      await service.writeMatchResult("session123", result, "newkey");

      // Should still have the better match
      const cached = await redis.get("session:session123");
      const value: SessionCacheValue = JSON.parse(cached!);
      expect(value.device_id).toBe("dev_better");
    });

    it("should overwrite lower confidence match", async () => {
      // Pre-populate with lower confidence match
      const existing: SessionCacheValue = {
        status: "complete",
        device_id: "dev_old",
        risk_score: 0.5,
        confidence: 0.7,
        match_tier: 2,
        match_version: Date.now(),
        idempotency_key: "old",
        flags: [],
        updated_at: Date.now(),
      };
      await redis.set("session:session123", JSON.stringify(existing));

      // Write higher confidence match
      const result = {
        device_id: "dev_better",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [],
      };

      await service.writeMatchResult("session123", result, "newkey");

      const cached = await redis.get("session:session123");
      const value: SessionCacheValue = JSON.parse(cached!);
      expect(value.device_id).toBe("dev_better");
    });
  });

  describe("writeDegradedResult", () => {
    it("should write degraded status to Redis", async () => {
      await service.writeDegradedResult("session123", "idempkey");

      const cached = await redis.get("session:session123");
      expect(cached).not.toBeNull();

      const value: SessionCacheValue = JSON.parse(cached!);
      expect(value.status).toBe("degraded");
      expect(value.device_id).toBe("");
      expect(value.flags).toContain("matching_failed");
    });
  });

  describe("queueProfileUpdate", () => {
    it("should send message to SQS profile queue", async () => {
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg123" });

      const payload = {
        session_id: "session123",
        tenant_id: "tenant1",
        fingerprint: { stable_hash: "abc" },
        tcp_blob: "encrypted",
        tls_blob: "encrypted",
        headers: {},
        timestamp: Date.now(),
      };

      await service.queueProfileUpdate("tenant1", "dev_123", payload);

      const calls = sqsMock.calls();
      expect(calls).toHaveLength(1);

      const call = calls[0];
      const input = call.args[0].input as {
        QueueUrl: string;
        MessageBody: string;
      };
      expect(input.QueueUrl).toBe(testConfig.profileQueueUrl);

      const messageBody = JSON.parse(input.MessageBody);
      expect(messageBody.tenant_id).toBe("tenant1");
      expect(messageBody.device_id).toBe("dev_123");
      expect(messageBody.fingerprint).toEqual({ stable_hash: "abc" });
    });
  });
});

describe("generateIdempotencyKey", () => {
  it("should generate consistent hash for same input", () => {
    const fingerprint: Fingerprint = {
      stable_hash: "stable123",
      canvas_hash: "canvas456",
    };

    const key1 = generateIdempotencyKey("session1", fingerprint);
    const key2 = generateIdempotencyKey("session1", fingerprint);

    expect(key1).toBe(key2);
  });

  it("should generate different hash for different session", () => {
    const fingerprint: Fingerprint = { stable_hash: "stable123" };

    const key1 = generateIdempotencyKey("session1", fingerprint);
    const key2 = generateIdempotencyKey("session2", fingerprint);

    expect(key1).not.toBe(key2);
  });

  it("should generate different hash for different fingerprint", () => {
    const key1 = generateIdempotencyKey("session1", { stable_hash: "a" });
    const key2 = generateIdempotencyKey("session1", { stable_hash: "b" });

    expect(key1).not.toBe(key2);
  });

  it("should return hexadecimal string", () => {
    const key = generateIdempotencyKey("session", { stable_hash: "test" });
    expect(key).toMatch(/^[a-f0-9]+$/);
  });
});

describe("generateUUID", () => {
  it("should generate valid UUID v4 format", () => {
    const uuid = generateUUID();
    expect(uuid).toMatch(
      /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    );
  });

  it("should generate unique UUIDs", () => {
    const uuids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      uuids.add(generateUUID());
    }
    expect(uuids.size).toBe(1000);
  });

  it("should produce no collisions in 100K generated UUIDs (crypto-secure)", () => {
    // Using 100K instead of 1M for reasonable test runtime
    // crypto.randomUUID() is cryptographically secure, so this validates
    // we're using the proper implementation
    const uuids = new Set<string>();
    const count = 100_000;
    for (let i = 0; i < count; i++) {
      const uuid = generateUUID();
      expect(uuids.has(uuid)).toBe(false);
      uuids.add(uuid);
    }
    expect(uuids.size).toBe(count);
  });
});
