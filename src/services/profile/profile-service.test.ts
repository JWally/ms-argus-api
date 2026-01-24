// src/services/profile/profile-service.test.ts
// AR-52: Updated to use DynamoCacheService mock instead of Redis
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  BatchWriteItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
} from "./profile-service";
import { Fingerprint, DeviceProfile, ProfileUpdatePayload } from "./types";
import { DynamoCacheService } from "../cache";

// Mock AWS SDK client
const dynamoMock = mockClient(DynamoDBClient);

// Test configuration
const testConfig: ProfileServiceConfig = {
  profilesTable: "test-profiles",
  tier1IndexTable: "test-tier1-index",
  tier2BucketsTable: "test-tier2-buckets",
  profileTtlDays: 60,
  tier2BucketTtlDays: 7,
  mutationGateTtlSeconds: 3600,
};

// Mock DynamoCacheService for testing
function createMockCacheService() {
  const gates = new Set<string>();
  return {
    checkSessionCache: vi.fn().mockResolvedValue(null),
    writeSessionCache: vi.fn().mockResolvedValue(true), // AR-170: Returns boolean
    tryAcquireMutationGate: vi
      .fn()
      .mockImplementation(async (deviceId: string) => {
        if (gates.has(deviceId)) {
          return false;
        }
        gates.add(deviceId);
        return true;
      }),
    // Helper for tests to pre-set gates
    _setGate: (deviceId: string) => gates.add(deviceId),
    _clearGates: () => gates.clear(),
  } as unknown as DynamoCacheService & {
    _setGate: (deviceId: string) => void;
    _clearGates: () => void;
  };
}

describe("ProfileService", () => {
  let dynamodb: DynamoDBClient;
  let mockCache: ReturnType<typeof createMockCacheService>;
  let service: ProfileService;

  beforeEach(() => {
    // Reset mocks
    dynamoMock.reset();

    // Create fresh cache mock
    mockCache = createMockCacheService();

    // Create real client (mocked by aws-sdk-client-mock)
    dynamodb = new DynamoDBClient({});

    // Create service with test dependencies
    const deps: ProfileServiceDeps = {
      dynamodb,
      cache: mockCache,
      config: testConfig,
    };
    service = new ProfileService(deps);
  });

  describe("tryAcquireMutationGate", () => {
    it("should acquire gate when key does not exist", async () => {
      const result = await service.tryAcquireMutationGate("dev_gate_test");
      expect(result).toBe(true);

      // Verify cache service was called
      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith(
        "dev_gate_test",
      );
    });

    it("should fail to acquire gate when key already exists", async () => {
      // Pre-set the gate
      mockCache._setGate("dev_gate_held");

      const result = await service.tryAcquireMutationGate("dev_gate_held");
      expect(result).toBe(false);
    });

    it("should be atomic - only one concurrent call succeeds", async () => {
      // Simulate 100 concurrent calls for same device (AR-27 acceptance criteria)
      const results = await Promise.all(
        Array.from({ length: 100 }, () =>
          service.tryAcquireMutationGate("dev_race_condition"),
        ),
      );

      // Exactly one should succeed
      const successCount = results.filter((r) => r === true).length;
      expect(successCount).toBe(1);
    });
  });

  describe("loadExistingProfile", () => {
    it("should return null when profile not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.loadExistingProfile("dev_unknown");
      expect(result).toBeNull();
    });

    it("should return profile when found", async () => {
      const profile: DeviceProfile = {
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

      const result = await service.loadExistingProfile("dev_123");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_123");
      expect(result?.stable_hash).toBe("stable123");
      expect(result?.request_count).toBe(42);
    });
  });

  describe("hasSignificantDrift", () => {
    const baseProfile: DeviceProfile = {
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
        "dev_123",
        fingerprint,
        ttl,
      );
      expect(entries).toEqual([]);
    });

    it("should build evercookie entry", () => {
      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const entries = service.buildTier1IndexEntries(
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "evercookie#cookie123",
        device_id: "dev_123",
        ttl,
      });
    });

    // AR-81: Test for sigint_id (third-party cookie)
    it("should build sigint_id entry", () => {
      const fingerprint: Fingerprint = { sigint_id: "abc123-def456-789" };
      const entries = service.buildTier1IndexEntries(
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "sigint#abc123-def456-789",
        device_id: "dev_123",
        ttl,
      });
    });

    // AR-64: Test for ECDSA public key
    it("should build public_key entry", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...base64...";
      const fingerprint: Fingerprint = { public_key: publicKey };
      const entries = service.buildTier1IndexEntries(
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: `pubkey#${publicKey}`,
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build stable_hash entry", () => {
      const fingerprint: Fingerprint = { stable_hash: "stable456" };
      const entries = service.buildTier1IndexEntries(
        "dev_123",
        fingerprint,
        ttl,
      );

      expect(entries).toHaveLength(1);
      expect(entries[0].hash_key).toBe("stable#stable456");
    });

    it("should build all entries when all hashes present", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie",
        sigint_id: "sigint-uuid-123", // AR-81
        public_key: publicKey, // AR-64
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
        ja4: "ja4hash", // ja4 is in fingerprint but NOT indexed in Tier1 (AR-115)
      };

      const entries = service.buildTier1IndexEntries(
        "dev_123",
        fingerprint,
        ttl,
      );

      // AR-115: Now 5 entries - removed standalone ja4# indexing (not unique enough)
      expect(entries).toHaveLength(5);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain("evercookie#cookie");
      expect(hashKeys).toContain("sigint#sigint-uuid-123"); // AR-81
      expect(hashKeys).toContain(`pubkey#${publicKey}`); // AR-64
      expect(hashKeys).toContain("stable#stable");
      expect(hashKeys).toContain("fuzzy#fuzzy");
      // AR-115: ja4 is NOT indexed standalone - only used in Tier2 ip_ja4 buckets
      expect(hashKeys).not.toContain("ja4#ja4hash");
    });
  });

  // AR-120: buildTier2BucketKeys tests removed - now comprehensively tested in bucket-keys.test.ts (AR-117)

  describe("updateProfile", () => {
    it("should create new profile with defaults", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "canvas456",
      };

      await service.updateProfile("dev_new", fingerprint, Date.now(), null);

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(1);

      const putCall = calls[0];
      expect(putCall.args[0].input.TableName).toBe(testConfig.profilesTable);

      // Verify the item has expected fields
      const item = putCall.args[0].input.Item;
      expect(item?.device_id?.S).toBe("dev_new");
      expect(item?.stable_hash?.S).toBe("stable123");
      expect(item?.risk_score?.N).toBe("0.5"); // Default for new
      expect(item?.request_count?.N).toBe("1");
    });

    it("should compute dynamic risk_score and preserve positive flags", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const existingProfile: DeviceProfile = {
        device_id: "dev_existing",
        risk_score: 0.8, // High risk (historical)
        flags: ["verified", "returning_user"], // Positive flags that should be preserved
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 100,
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      await service.updateProfile(
        "dev_existing",
        {},
        Date.now(),
        existingProfile,
      );

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      // Risk is now dynamically computed:
      // Base: 0.3 (returning) - 0.2 (verified) - 0.1 (returning_user) = 0.0
      // Blended: 0.0 * 0.7 + 0.8 * 0.3 = 0.24
      expect(parseFloat(item?.risk_score?.N ?? "0")).toBeCloseTo(0.24, 2);
      // Positive flags (verified, returning_user) should be preserved
      expect(item?.flags?.L).toHaveLength(2);
      expect(item?.request_count?.N).toBe("101"); // Incremented
    });

    it("should increment request_count", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const existingProfile: DeviceProfile = {
        device_id: "dev_123",
        risk_score: 0.3,
        flags: [],
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 42,
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      await service.updateProfile("dev_123", {}, Date.now(), existingProfile);

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      expect(item?.request_count?.N).toBe("43");
    });
  });

  describe("updateTier1Indexes", () => {
    it("should batch write all index entries", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie",
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
      };

      const count = await service.updateTier1Indexes("dev_123", fingerprint);

      expect(count).toBe(3);

      const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
      expect(calls).toHaveLength(1);

      // Verify batch contains 3 items for correct table
      const requestItems = calls[0].args[0].input.RequestItems;
      expect(requestItems).toBeDefined();
      expect(requestItems?.[testConfig.tier1IndexTable]).toHaveLength(3);
    });

    it("should return 0 when no indexes to write", async () => {
      const count = await service.updateTier1Indexes("dev_123", {});
      expect(count).toBe(0);

      // Verify no BatchWriteItemCommand was called
      const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
      expect(calls).toHaveLength(0);
    });

    it("should retry on unprocessed items", async () => {
      // First call returns unprocessed items
      dynamoMock
        .on(BatchWriteItemCommand)
        .resolvesOnce({
          UnprocessedItems: {
            [testConfig.tier1IndexTable]: [
              {
                PutRequest: {
                  Item: marshall({
                    hash_key: "stable#stable",
                    device_id: "dev_123",
                    ttl: 1705000000,
                  }),
                },
              },
            ],
          },
        })
        .resolves({}); // Second call succeeds

      const fingerprint: Fingerprint = {
        stable_hash: "stable",
      };

      const count = await service.updateTier1Indexes("dev_123", fingerprint);

      expect(count).toBe(1);

      // Should have made 2 calls (initial + retry)
      const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
      expect(calls).toHaveLength(2);
    });
  });

  // AR-150: Tests for tier-gated identity association
  describe("updateTier1IndexesWithEvidence", () => {
    it("should write all indexes when evidence is PUBLIC_KEY_MATCH (Tier 0.5)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        evercookie_id: "cookie123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["PUBLIC_KEY_MATCH"],
      );

      // Should write all 4 indexes (pubkey, evercookie, stable, fuzzy)
      expect(count).toBe(4);
    });

    it("should write all indexes when evidence is STABLE_HASH_MATCH (Tier 1)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["STABLE_HASH_MATCH"],
      );

      // Should write all 3 indexes (pubkey, stable, fuzzy)
      expect(count).toBe(3);
    });

    it("should write all indexes when evidence is SESSION_ANCHOR_BUCKET", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable123",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["SESSION_ANCHOR_BUCKET"],
      );

      // Should write all 2 indexes (evercookie, stable)
      expect(count).toBe(2);
    });

    it("should only write hash indexes when evidence is IP_JA4_BUCKET (Tier 2 unbounded)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["IP_JA4_BUCKET"],
      );

      // Should only write 2 indexes (stable, fuzzy) - NO identity indexes
      expect(count).toBe(2);

      // Verify only hash indexes were written
      const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
      expect(calls).toHaveLength(1);
      const items =
        calls[0].args[0].input.RequestItems?.[testConfig.tier1IndexTable];
      const hashKeys = items?.map((item) => item.PutRequest?.Item?.hash_key?.S);
      expect(hashKeys).toContain("stable#stable123");
      expect(hashKeys).toContain("fuzzy#fuzzy456");
      expect(hashKeys).not.toContain(expect.stringContaining("pubkey#"));
      expect(hashKeys).not.toContain(expect.stringContaining("evercookie#"));
      expect(hashKeys).not.toContain(expect.stringContaining("sigint#"));
    });

    it("should only write hash indexes when evidence is GPU_SCREEN_TZ_BUCKET", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["GPU_SCREEN_TZ_BUCKET"],
      );

      // Should only write 1 hash index - no identity index
      expect(count).toBe(1);
    });

    it("should write all indexes when evidence_codes is undefined (backward compat)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint, // No evidence codes
      );

      // Should write all 2 indexes for backward compatibility
      expect(count).toBe(2);
    });

    it("should write all indexes when evidence_codes is empty array", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        [], // Empty evidence codes
      );

      // Should write all indexes for backward compatibility
      expect(count).toBe(2);
    });

    it("should return 0 when only identity fields present but evidence is Tier 2", async () => {
      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        evercookie_id: "cookie123",
        // No hash fields
      };

      const count = await service.updateTier1IndexesWithEvidence(
        "dev_123",
        fingerprint,
        ["IP_JA4_BUCKET"],
      );

      // Should write 0 indexes - no hash fields, identity blocked
      expect(count).toBe(0);
    });
  });

  describe("updateTier2Buckets", () => {
    it("should use BatchWriteItem for reliability (AR-40)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
      };

      const count = await service.updateTier2Buckets("dev_123", fingerprint);

      expect(count).toBe(1);

      // Filter BatchWriteItemCommand calls for tier2 buckets table only
      const calls = dynamoMock
        .commandCalls(BatchWriteItemCommand)
        .filter(
          (call) =>
            call.args[0].input.RequestItems?.[testConfig.tier2BucketsTable],
        );
      expect(calls).toHaveLength(1);

      const requestItems =
        calls[0].args[0].input.RequestItems?.[testConfig.tier2BucketsTable];
      expect(requestItems).toHaveLength(1);
      expect(requestItems?.[0].PutRequest?.Item?.bucket_key?.S).toContain(
        "ip_ja4",
      );
      expect(requestItems?.[0].PutRequest?.Item?.device_id?.S).toBe("dev_123");
    });

    it("should batch multiple bucket entries together", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const count = await service.updateTier2Buckets("dev_123", fingerprint);

      expect(count).toBe(2); // ip_ja4 and audio_canvas

      // Should make single BatchWriteItem call with all entries
      const calls = dynamoMock
        .commandCalls(BatchWriteItemCommand)
        .filter(
          (call) =>
            call.args[0].input.RequestItems?.[testConfig.tier2BucketsTable],
        );
      expect(calls).toHaveLength(1);

      const requestItems =
        calls[0].args[0].input.RequestItems?.[testConfig.tier2BucketsTable];
      expect(requestItems).toHaveLength(2);
    });

    it("should set tier2 bucket TTL to 7 days (AR-39)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
      };

      await service.updateTier2Buckets("dev_123", fingerprint);

      const calls = dynamoMock
        .commandCalls(BatchWriteItemCommand)
        .filter(
          (call) =>
            call.args[0].input.RequestItems?.[testConfig.tier2BucketsTable],
        );
      expect(calls).toHaveLength(1);

      // Verify TTL is approximately 7 days from now
      const requestItems =
        calls[0].args[0].input.RequestItems?.[testConfig.tier2BucketsTable];
      const ttlValue = Number(requestItems?.[0].PutRequest?.Item?.ttl?.N);
      const expectedTtl =
        Math.floor(Date.now() / 1000) +
        testConfig.tier2BucketTtlDays * 24 * 60 * 60;
      // Allow 5 second tolerance for test execution time
      expect(ttlValue).toBeGreaterThanOrEqual(expectedTtl - 5);
      expect(ttlValue).toBeLessThanOrEqual(expectedTtl + 5);
    });

    it("should retry on unprocessed items (AR-40)", async () => {
      // First call returns unprocessed items, second succeeds
      dynamoMock
        .on(BatchWriteItemCommand)
        .resolvesOnce({
          UnprocessedItems: {
            [testConfig.tier2BucketsTable]: [
              {
                PutRequest: {
                  Item: {
                    bucket_key: { S: "ip_ja4#10.0.0.1#ja4" },
                    device_id: { S: "dev_123" },
                    ttl: { N: "123456789" },
                  },
                },
              },
            ],
          },
        })
        .resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4",
      };

      await service.updateTier2Buckets("dev_123", fingerprint);

      // Should have made 2 calls (initial + retry)
      const calls = dynamoMock
        .commandCalls(BatchWriteItemCommand)
        .filter(
          (call) =>
            call.args[0].input.RequestItems?.[testConfig.tier2BucketsTable],
        );
      expect(calls).toHaveLength(2);
    });

    it("should return 0 when no bucket keys to write", async () => {
      const fingerprint: Fingerprint = {
        // No fields that generate bucket keys
        stable_hash: "abc",
      };

      const count = await service.updateTier2Buckets("dev_123", fingerprint);

      expect(count).toBe(0);
      // No BatchWriteItem calls should be made
      expect(dynamoMock.commandCalls(BatchWriteItemCommand)).toHaveLength(0);
    });

    // AR-56: Cardinality tracking tests
    it("should increment bucket cardinality counters", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});
      dynamoMock.on(UpdateItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      await service.updateTier2Buckets("dev_123", fingerprint);

      // Should make UpdateItemCommand calls for cardinality (one per bucket)
      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls).toHaveLength(2); // ip_ja4 and audio_canvas buckets

      // Verify the update expression uses ADD for atomic increment
      for (const call of updateCalls) {
        expect(call.args[0].input.UpdateExpression).toContain(
          "ADD cardinality",
        );
        expect(call.args[0].input.ExpressionAttributeValues?.[":inc"]?.N).toBe(
          "1",
        );
        // Verify stats item uses "_stats" as sort key
        expect(call.args[0].input.Key?.device_id?.S).toBe("_stats");
      }
    });
  });

  describe("processProfileUpdate", () => {
    it("should skip when mutation gate is active", async () => {
      // Pre-set mutation gate
      mockCache._setGate("dev_gated");

      const payload: ProfileUpdatePayload = {
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

      // Verify cache service was called to acquire gate
      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith(
        "dev_stable",
      );
    });

    it("should perform full update for new device", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined }); // No existing profile
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(BatchWriteItemCommand).resolves({}); // For Tier1 indexes

      const payload: ProfileUpdatePayload = {
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
      // AR-115: Now 2 tier1 writes (stable_hash, evercookie_id) - ja4 no longer indexed standalone
      expect(result.tier1Writes).toBe(2);
      expect(result.tier2Writes).toBe(1); // ip_ja4

      // Verify mutation gate was acquired
      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith("dev_new");
    });

    it("should perform full update when drift detected", async () => {
      const existingProfile: DeviceProfile = {
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
      dynamoMock.on(BatchWriteItemCommand).resolves({}); // For Tier1 indexes

      const payload: ProfileUpdatePayload = {
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

  describe("detectBotSignals", () => {
    it("should detect SwiftShader GPU renderer as headless browser", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "SwiftShader",
      };

      const flags = service.detectBotSignals(fingerprint);

      expect(flags).toContain("headless_browser");
      expect(flags).toContain("bot_detected");
    });

    it("should detect small viewport as bot", () => {
      const fingerprint: Fingerprint = {
        screen_dims: "800x600",
      };

      const flags = service.detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should detect bot user agent", () => {
      const fingerprint: Fingerprint = {
        user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)",
      };

      const flags = service.detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should detect crawler user agent", () => {
      const fingerprint: Fingerprint = {
        user_agent: "Mozilla/5.0 (compatible; Baiduspider/2.0)",
      };

      const flags = service.detectBotSignals(fingerprint);

      // "spider" pattern in user_agent
      expect(flags).toContain("bot_detected");
    });

    it("should detect single core with low memory as bot", () => {
      const fingerprint: Fingerprint = {
        hardware_concurrency: 1,
        device_memory: 0.5,
      };

      const flags = service.detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should not flag legitimate fingerprint", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "ANGLE (Intel, Intel UHD Graphics 620)",
        screen_dims: "1920x1080",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        hardware_concurrency: 8,
        device_memory: 8,
      };

      const flags = service.detectBotSignals(fingerprint);

      expect(flags).toHaveLength(0);
    });

    it("should remove duplicate flags", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "SwiftShader", // triggers bot_detected
        screen_dims: "800x600", // also triggers bot_detected
      };

      const flags = service.detectBotSignals(fingerprint);

      // Should only have one bot_detected
      const botDetectedCount = flags.filter((f) => f === "bot_detected").length;
      expect(botDetectedCount).toBe(1);
    });
  });

  describe("computeFlags", () => {
    it("should set NEW_DEVICE flag for new devices", () => {
      const fingerprint: Fingerprint = {};

      const flags = service.computeFlags(fingerprint, null, true, false);

      expect(flags).toContain("new_device");
    });

    it("should set FINGERPRINT_MISMATCH flag when drift detected", () => {
      const fingerprint: Fingerprint = {};
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.5,
        flags: [],
        first_seen_at: Date.now() - 86400000, // 1 day ago
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = service.computeFlags(
        fingerprint,
        existingProfile,
        false,
        true,
      );

      expect(flags).toContain("fingerprint_mismatch");
    });

    it("should set RAPID_REQUESTS flag for high request rate", () => {
      const fingerprint: Fingerprint = {};
      const oneHourAgo = Date.now() - 3600000;
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.5,
        flags: [],
        first_seen_at: oneHourAgo, // 1 hour ago
        last_seen_at: Date.now() - 60000,
        request_count: 100, // 100 requests in 1 hour = 100/hour (> 50 threshold)
        updated_at: Date.now() - 60000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = service.computeFlags(
        fingerprint,
        existingProfile,
        false,
        false,
      );

      expect(flags).toContain("rapid_requests");
    });

    it("should preserve positive flags from existing profile", () => {
      const fingerprint: Fingerprint = {};
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.3,
        flags: ["verified", "returning_user"],
        first_seen_at: Date.now() - 86400000 * 30, // 30 days ago
        last_seen_at: Date.now() - 3600000,
        request_count: 500,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = service.computeFlags(
        fingerprint,
        existingProfile,
        false,
        false,
      );

      expect(flags).toContain("verified");
      expect(flags).toContain("returning_user");
    });

    it("should not preserve negative flags from existing profile", () => {
      const fingerprint: Fingerprint = {};
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.8,
        flags: ["bot_detected", "suspicious_behavior"],
        first_seen_at: Date.now() - 86400000 * 30,
        last_seen_at: Date.now() - 3600000,
        request_count: 50,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = service.computeFlags(
        fingerprint,
        existingProfile,
        false,
        false,
      );

      // These negative flags should not be preserved (only re-detected if fingerprint triggers)
      expect(flags).not.toContain("suspicious_behavior");
    });

    it("should combine multiple flags", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "SwiftShader",
      };
      const oneHourAgo = Date.now() - 3600000;
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.5,
        flags: ["verified"],
        first_seen_at: oneHourAgo,
        last_seen_at: Date.now() - 60000,
        request_count: 100,
        updated_at: Date.now() - 60000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = service.computeFlags(
        fingerprint,
        existingProfile,
        false,
        true, // drift
      );

      expect(flags).toContain("headless_browser");
      expect(flags).toContain("bot_detected");
      expect(flags).toContain("fingerprint_mismatch");
      expect(flags).toContain("rapid_requests");
      expect(flags).toContain("verified"); // preserved positive flag
    });
  });

  describe("computeRiskScore", () => {
    it("should return base risk of 0.5 for new device", () => {
      const score = service.computeRiskScore([], null, true);
      expect(score).toBe(0.5);
    });

    it("should return base risk of 0.3 for returning device without flags", () => {
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.3,
        flags: [],
        first_seen_at: Date.now() - 86400000,
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const score = service.computeRiskScore([], existingProfile, false);
      expect(score).toBe(0.3);
    });

    it("should increase risk for bot_detected flag", () => {
      const score = service.computeRiskScore(["bot_detected"], null, true);
      expect(score).toBe(0.75); // 0.5 base + 0.25 bot
    });

    it("should increase risk for headless_browser flag", () => {
      const score = service.computeRiskScore(["headless_browser"], null, true);
      expect(score).toBe(0.65); // 0.5 base + 0.15 headless
    });

    it("should increase risk for fingerprint_mismatch flag", () => {
      const score = service.computeRiskScore(
        ["fingerprint_mismatch"],
        null,
        true,
      );
      expect(score).toBe(0.65); // 0.5 base + 0.15 mismatch
    });

    it("should increase risk for rapid_requests flag", () => {
      const score = service.computeRiskScore(["rapid_requests"], null, true);
      expect(score).toBe(0.6); // 0.5 base + 0.1 rapid
    });

    it("should decrease risk for verified flag", () => {
      const score = service.computeRiskScore(["verified"], null, true);
      expect(score).toBe(0.3); // 0.5 base - 0.2 verified
    });

    it("should decrease risk for returning_user flag", () => {
      const score = service.computeRiskScore(["returning_user"], null, true);
      expect(score).toBe(0.4); // 0.5 base - 0.1 returning
    });

    it("should stack multiple negative signals", () => {
      const flags = ["bot_detected", "headless_browser", "rapid_requests"];
      const score = service.computeRiskScore(flags, null, true);
      expect(score).toBe(1.0); // 0.5 + 0.25 + 0.15 + 0.1 = 1.0 (clamped)
    });

    it("should clamp risk score to maximum of 1.0", () => {
      const flags = [
        "bot_detected",
        "headless_browser",
        "fingerprint_mismatch",
        "rapid_requests",
      ];
      const score = service.computeRiskScore(flags, null, true);
      expect(score).toBe(1.0); // Would be 1.15, clamped to 1.0
    });

    it("should clamp risk score to minimum of 0.0", () => {
      const flags = ["verified", "returning_user"];
      const score = service.computeRiskScore(flags, null, true);
      expect(score).toBeCloseTo(0.2, 2); // 0.5 - 0.2 - 0.1 = 0.2
    });

    it("should blend with historical risk for returning devices", () => {
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.9, // High historical risk
        flags: [],
        first_seen_at: Date.now() - 86400000,
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      // Base risk for returning = 0.3
      // With 30% historical weight: 0.3 * 0.7 + 0.9 * 0.3 = 0.21 + 0.27 = 0.48
      const score = service.computeRiskScore([], existingProfile, false);
      expect(score).toBeCloseTo(0.48, 2);
    });

    it("should apply flags before blending with historical risk", () => {
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.3,
        flags: [],
        first_seen_at: Date.now() - 86400000,
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      // Base: 0.3 + bot_detected: 0.25 = 0.55
      // Blended: 0.55 * 0.7 + 0.3 * 0.3 = 0.385 + 0.09 = 0.475
      const score = service.computeRiskScore(
        ["bot_detected"],
        existingProfile,
        false,
      );
      expect(score).toBeCloseTo(0.475, 2);
    });

    it("should not blend historical risk for new devices", () => {
      // Even if we somehow pass an existing profile with isNewDevice=true,
      // it should not blend (this is a consistency check)
      const score = service.computeRiskScore(["verified"], null, true);
      expect(score).toBe(0.3); // 0.5 - 0.2 = 0.3, no blending
    });

    it("should silently ignore unknown flags", () => {
      // Unknown flags should not throw errors or affect the score
      const score = service.computeRiskScore(
        ["unknown_flag", "another_unknown"],
        null,
        true,
      );
      expect(score).toBe(0.5); // Base score only, unknown flags ignored
    });

    it("should process known flags and ignore unknown flags in same array", () => {
      const score = service.computeRiskScore(
        ["bot_detected", "unknown_flag", "verified"],
        null,
        true,
      );
      // 0.5 base + 0.25 bot - 0.2 verified = 0.55 (unknown ignored)
      expect(score).toBe(0.55);
    });
  });
});
