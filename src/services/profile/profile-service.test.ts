// src/services/profile/profile-service.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import RedisMock from "ioredis-mock";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
} from "./profile-service";
import { Fingerprint, DeviceProfile, ProfileUpdatePayload } from "./types";

// Mock AWS SDK client
const dynamoMock = mockClient(DynamoDBClient);

// Test configuration
const testConfig: ProfileServiceConfig = {
  profilesTable: "test-profiles",
  tier1IndexTable: "test-tier1-index",
  tier2BucketsTable: "test-tier2-buckets",
  profileTtlDays: 60,
  mutationGateTtlSeconds: 3600,
};

describe("ProfileService", () => {
  let redis: InstanceType<typeof RedisMock>;
  let dynamodb: DynamoDBClient;
  let service: ProfileService;

  beforeEach(() => {
    // Reset mocks
    dynamoMock.reset();

    // Create fresh Redis mock
    redis = new RedisMock();

    // Create real client (mocked by aws-sdk-client-mock)
    dynamodb = new DynamoDBClient({});

    // Create service with test dependencies
    const deps: ProfileServiceDeps = {
      dynamodb,
      redis: redis as any,
      config: testConfig,
    };
    service = new ProfileService(deps);
  });

  afterEach(async () => {
    await redis.quit();
  });

  describe("checkMutationGate", () => {
    it("should return true when device not recently updated", async () => {
      const result = await service.checkMutationGate("dev_new");
      expect(result).toBe(true);
    });

    it("should return false when device was recently updated", async () => {
      await redis.setex("recently_updated:dev_recent", 3600, "1");

      const result = await service.checkMutationGate("dev_recent");
      expect(result).toBe(false);
    });
  });

  describe("setMutationGate", () => {
    it("should set key with TTL", async () => {
      await service.setMutationGate("dev_123");

      const value = await redis.get("recently_updated:dev_123");
      expect(value).toBe("1");

      const ttl = await redis.ttl("recently_updated:dev_123");
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(3600);
    });
  });

  describe("loadExistingProfile", () => {
    it("should return null when profile not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.loadExistingProfile(
        "tenant1",
        "dev_unknown",
      );
      expect(result).toBeNull();
    });

    it("should return profile when found", async () => {
      const profile: DeviceProfile = {
        tenant_id: "tenant1",
        device_id: "dev_123",
        stable_hash: "stable123",
        canvas_hash: "canvas456",
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 42,
        risk_score: 0.3,
        flags: ["verified"],
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall(profile),
      });

      const result = await service.loadExistingProfile("tenant1", "dev_123");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_123");
      expect(result?.stable_hash).toBe("stable123");
      expect(result?.request_count).toBe(42);
    });
  });

  describe("hasSignificantDrift", () => {
    const baseProfile: DeviceProfile = {
      tenant_id: "tenant1",
      device_id: "dev_123",
      stable_hash: "stable123",
      canvas_hash: "canvas456",
      webgl_hash: "webgl789",
      audio_hash: "audio012",
      gpu_renderer: "Intel UHD",
      screen_dims: "1920x1080",
      first_seen_at: 1700000000000,
      last_seen_at: 1700100000000,
      request_count: 10,
      risk_score: 0.3,
      flags: [],
      updated_at: 1700100000000,
      ttl: 1705000000,
    };

    it("should return true when stable_hash changes (major drift)", () => {
      const incoming: Fingerprint = {
        stable_hash: "different_hash", // Changed!
        canvas_hash: "canvas456",
        webgl_hash: "webgl789",
      };

      expect(service.hasSignificantDrift(baseProfile, incoming)).toBe(true);
    });

    it("should return false when only one signal changes", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different_canvas", // 1 change
        webgl_hash: "webgl789",
        audio_hash: "audio012",
        gpu_renderer: "Intel UHD",
        screen_dims: "1920x1080",
      };

      expect(service.hasSignificantDrift(baseProfile, incoming)).toBe(false);
    });

    it("should return true when 2+ signals change", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different_canvas", // Change 1
        webgl_hash: "different_webgl", // Change 2
        audio_hash: "audio012",
        gpu_renderer: "Intel UHD",
        screen_dims: "1920x1080",
      };

      expect(service.hasSignificantDrift(baseProfile, incoming)).toBe(true);
    });

    it("should return true when 3+ signals change", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different1",
        webgl_hash: "different2",
        audio_hash: "different3",
      };

      expect(service.hasSignificantDrift(baseProfile, incoming)).toBe(true);
    });

    it("should return false when fingerprint is identical", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "canvas456",
        webgl_hash: "webgl789",
        audio_hash: "audio012",
        gpu_renderer: "Intel UHD",
        screen_dims: "1920x1080",
      };

      expect(service.hasSignificantDrift(baseProfile, incoming)).toBe(false);
    });
  });

  describe("buildTier1IndexEntries", () => {
    const ttl = 1705000000;

    it("should return empty array when no hashes present", () => {
      const fingerprint: Fingerprint = {};
      const entries = service.buildTier1IndexEntries(
        "tenant1",
        "dev_123",
        fingerprint,
        ttl,
      );
      expect(entries).toEqual([]);
    });

    it("should build evercookie entry", () => {
      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const entries = service.buildTier1IndexEntries(
        "tenant1",
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        tenant_id: "tenant1",
        hash_key: "evercookie#cookie123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build stable_hash entry", () => {
      const fingerprint: Fingerprint = { stable_hash: "stable456" };
      const entries = service.buildTier1IndexEntries(
        "tenant1",
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0].hash_key).toBe("stable#stable456");
    });

    it("should build all entries when all hashes present", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie",
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
        ja4: "ja4hash",
      };

      const entries = service.buildTier1IndexEntries(
        "tenant1",
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(4);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain("evercookie#cookie");
      expect(hashKeys).toContain("stable#stable");
      expect(hashKeys).toContain("fuzzy#fuzzy");
      expect(hashKeys).toContain("ja4#ja4hash");
    });
  });

  describe("buildTier2BucketKeys", () => {
    it("should return empty array when no compound signals", () => {
      const fingerprint: Fingerprint = {};
      const keys = service.buildTier2BucketKeys("tenant1", fingerprint);
      expect(keys).toEqual([]);
    });

    it("should build ip_ja4 bucket key", () => {
      const fingerprint: Fingerprint = {
        ip_address: "192.168.1.100",
        ja4: "t13d1516h2_abc123",
      };

      const keys = service.buildTier2BucketKeys("tenant1", fingerprint);

      expect(keys).toHaveLength(1);
      expect(keys[0]).toBe("tenant1#ip_ja4#192.168.1.100#t13d1516h2_abc123");
    });

    it("should build gpu_screen_tz bucket key", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "NVIDIA GeForce RTX 3080",
        screen_dims: "2560x1440",
        timezone: "America/Los_Angeles",
      };

      const keys = service.buildTier2BucketKeys("tenant1", fingerprint);

      expect(keys).toHaveLength(1);
      expect(keys[0]).toContain("gpu_screen_tz");
      expect(keys[0]).toContain("2560x1440");
    });

    it("should build audio_canvas bucket key", () => {
      const fingerprint: Fingerprint = {
        audio_hash: "audio123",
        canvas_hash: "canvas456",
      };

      const keys = service.buildTier2BucketKeys("tenant1", fingerprint);

      expect(keys).toHaveLength(1);
      expect(keys[0]).toBe("tenant1#audio_canvas#audio123#canvas456");
    });

    it("should build all bucket keys when all signals present", () => {
      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "UTC",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const keys = service.buildTier2BucketKeys("tenant1", fingerprint);
      expect(keys).toHaveLength(3);
    });
  });

  describe("updateProfile", () => {
    it("should create new profile with defaults", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "canvas456",
      };

      await service.updateProfile(
        "tenant1",
        "dev_new",
        fingerprint,
        Date.now(),
        null,
      );

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(1);

      const putCall = calls[0];
      expect(putCall.args[0].input.TableName).toBe(testConfig.profilesTable);

      // Verify the item has expected fields
      const item = putCall.args[0].input.Item;
      expect(item?.tenant_id?.S).toBe("tenant1");
      expect(item?.device_id?.S).toBe("dev_new");
      expect(item?.stable_hash?.S).toBe("stable123");
      expect(item?.risk_score?.N).toBe("0.5"); // Default for new
      expect(item?.request_count?.N).toBe("1");
    });

    it("should preserve existing risk_score and flags", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const existingProfile: DeviceProfile = {
        tenant_id: "tenant1",
        device_id: "dev_existing",
        risk_score: 0.8, // High risk
        flags: ["bot_detected", "suspicious"],
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 100,
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      await service.updateProfile(
        "tenant1",
        "dev_existing",
        {},
        Date.now(),
        existingProfile,
      );

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      expect(item?.risk_score?.N).toBe("0.8");
      expect(item?.flags?.L).toHaveLength(2);
      expect(item?.request_count?.N).toBe("101"); // Incremented
    });

    it("should increment request_count", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const existingProfile: DeviceProfile = {
        tenant_id: "tenant1",
        device_id: "dev_123",
        risk_score: 0.3,
        flags: [],
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 42,
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      await service.updateProfile(
        "tenant1",
        "dev_123",
        {},
        Date.now(),
        existingProfile,
      );

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      expect(item?.request_count?.N).toBe("43");
    });
  });

  describe("updateTier1Indexes", () => {
    it("should write all index entries", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie",
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
      };

      const count = await service.updateTier1Indexes(
        "tenant1",
        "dev_123",
        fingerprint,
      );

      expect(count).toBe(3);

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(3);

      // Verify correct table
      for (const call of calls) {
        expect(call.args[0].input.TableName).toBe(testConfig.tier1IndexTable);
      }
    });

    it("should return 0 when no indexes to write", async () => {
      const count = await service.updateTier1Indexes("tenant1", "dev_123", {});
      expect(count).toBe(0);
    });
  });

  describe("updateTier2Buckets", () => {
    it("should use PutItem for adjacency list pattern", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
      };

      const count = await service.updateTier2Buckets(
        "tenant1",
        "dev_123",
        fingerprint,
      );

      expect(count).toBe(1);

      // Filter PutItemCommand calls for tier2 buckets table only
      const calls = dynamoMock
        .commandCalls(PutItemCommand)
        .filter(
          (call) =>
            call.args[0].input.TableName === testConfig.tier2BucketsTable,
        );
      expect(calls).toHaveLength(1);

      const call = calls[0];
      expect(call.args[0].input.Item?.bucket_key?.S).toContain("ip_ja4");
      expect(call.args[0].input.Item?.device_id?.S).toBe("dev_123");
    });

    it("should insert multiple bucket entries in parallel", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const count = await service.updateTier2Buckets(
        "tenant1",
        "dev_123",
        fingerprint,
      );

      expect(count).toBe(2); // ip_ja4 and audio_canvas

      // Filter PutItemCommand calls for tier2 buckets table only
      const calls = dynamoMock
        .commandCalls(PutItemCommand)
        .filter(
          (call) =>
            call.args[0].input.TableName === testConfig.tier2BucketsTable,
        );
      expect(calls).toHaveLength(2);
    });
  });

  describe("processProfileUpdate", () => {
    it("should skip when mutation gate is active", async () => {
      // Set mutation gate
      await redis.setex("recently_updated:dev_gated", 3600, "1");

      const payload: ProfileUpdatePayload = {
        tenant_id: "tenant1",
        device_id: "dev_gated",
        fingerprint: { stable_hash: "abc" },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(true);
      expect(result.reason).toBe("mutation_gate");

      // Verify no DynamoDB calls were made
      expect(dynamoMock.calls()).toHaveLength(0);
    });

    it("should skip when no significant drift", async () => {
      const existingProfile: DeviceProfile = {
        tenant_id: "tenant1",
        device_id: "dev_stable",
        stable_hash: "same_hash",
        canvas_hash: "same_canvas",
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 50,
        risk_score: 0.3,
        flags: [],
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall(existingProfile),
      });

      const payload: ProfileUpdatePayload = {
        tenant_id: "tenant1",
        device_id: "dev_stable",
        fingerprint: {
          stable_hash: "same_hash", // Same as existing
          canvas_hash: "same_canvas", // Same as existing
        },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(true);
      expect(result.reason).toBe("no_drift");

      // Should have set mutation gate
      const gateExists = await redis.exists("recently_updated:dev_stable");
      expect(gateExists).toBe(1);
    });

    it("should perform full update for new device", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined }); // No existing profile
      dynamoMock.on(PutItemCommand).resolves({});

      const payload: ProfileUpdatePayload = {
        tenant_id: "tenant1",
        device_id: "dev_new",
        fingerprint: {
          stable_hash: "new_stable",
          evercookie_id: "cookie123",
          ip_address: "10.0.0.1",
          ja4: "ja4hash",
        },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(false);
      expect(result.tier1Writes).toBe(3); // stable_hash, evercookie_id, and ja4
      expect(result.tier2Writes).toBe(1); // ip_ja4

      // Verify mutation gate was set
      const gateExists = await redis.exists("recently_updated:dev_new");
      expect(gateExists).toBe(1);
    });

    it("should perform full update when drift detected", async () => {
      const existingProfile: DeviceProfile = {
        tenant_id: "tenant1",
        device_id: "dev_drift",
        stable_hash: "old_hash", // Will change
        canvas_hash: "old_canvas",
        webgl_hash: "old_webgl",
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 10,
        risk_score: 0.3,
        flags: [],
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall(existingProfile),
      });
      dynamoMock.on(PutItemCommand).resolves({});

      const payload: ProfileUpdatePayload = {
        tenant_id: "tenant1",
        device_id: "dev_drift",
        fingerprint: {
          stable_hash: "new_hash", // Major drift!
          canvas_hash: "new_canvas",
          webgl_hash: "new_webgl",
        },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(false);
      expect(result.tier1Writes).toBe(1); // stable_hash
    });
  });
});
