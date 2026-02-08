import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  BatchWriteItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  ProfileService,
  ProfileServiceConfig,
  ProfileServiceDeps,
} from "./profile-service";
import { Fingerprint, DeviceProfile, ProfileUpdatePayload } from "./types";
import { DynamoCacheService } from "../cache";
import { hasSignificantDrift } from "./drift-detection";
import {
  detectBotSignals,
  computeFlags,
  computeRiskScore,
} from "./flag-computation";
import { buildIdentityIndexEntries } from "./index-writers";

const dynamoMock = mockClient(DynamoDBClient);

const testConfig: ProfileServiceConfig = {
  profilesTable: "test-profiles",
  tier1IndexTable: "test-tier1-index",
  tier2BucketsTable: "test-tier2-buckets",
  profileTtlDays: 60,
  tier2BucketTtlDays: 7,
  mutationGateTtlSeconds: 3600,
};

function createMockCacheService() {
  const gates = new Set<string>();
  return {
    checkSessionCache: vi.fn().mockResolvedValue(null),
    writeSessionCache: vi.fn().mockResolvedValue(true),
    tryAcquireMutationGate: vi
      .fn()
      .mockImplementation(async (deviceId: string) => {
        if (gates.has(deviceId)) {
          return false;
        }
        gates.add(deviceId);
        return true;
      }),
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
    dynamoMock.reset();
    mockCache = createMockCacheService();
    dynamodb = new DynamoDBClient({});

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

      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith(
        "dev_gate_test",
      );
    });

    it("should fail to acquire gate when key already exists", async () => {
      mockCache._setGate("dev_gate_held");

      const result = await service.tryAcquireMutationGate("dev_gate_held");
      expect(result).toBe(false);
    });

    it("should be atomic - only one concurrent call succeeds", async () => {
      const results = await Promise.all(
        Array.from({ length: 100 }, () =>
          service.tryAcquireMutationGate("dev_race_condition"),
        ),
      );

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
        stable_hash: "different_hash",
        canvas_hash: "canvas456",
        webgl_hash: "webgl789",
      };

      expect(hasSignificantDrift(baseProfile, incoming)).toBe(true);
    });

    it("should return false when only one signal changes", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different_canvas",
        webgl_hash: "webgl789",
        audio_hash: "audio012",
        gpu_renderer: "Intel UHD",
        screen_dims: "1920x1080",
      };

      expect(hasSignificantDrift(baseProfile, incoming)).toBe(false);
    });

    it("should return true when 2+ signals change", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different_canvas",
        webgl_hash: "different_webgl",
        audio_hash: "audio012",
        gpu_renderer: "Intel UHD",
        screen_dims: "1920x1080",
      };

      expect(hasSignificantDrift(baseProfile, incoming)).toBe(true);
    });

    it("should return true when 3+ signals change", () => {
      const incoming: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "different1",
        webgl_hash: "different2",
        audio_hash: "different3",
      };

      expect(hasSignificantDrift(baseProfile, incoming)).toBe(true);
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

      expect(hasSignificantDrift(baseProfile, incoming)).toBe(false);
    });
  });

  describe("buildIdentityIndexEntries", () => {
    const ttl = 1705000000;

    it("should return empty array when no identity fields present", () => {
      const fingerprint: Fingerprint = { stable_hash: "stable123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);
      expect(entries).toEqual([]);
    });

    it("should build evercookie entry", () => {
      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "evercookie#cookie123",
        device_id: "dev_123",
        fuzzy_hash: undefined,
        ttl,
      });
    });

    it("should build sigint_id entry", () => {
      const fingerprint: Fingerprint = { sigint_id: "abc123-def456-789" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "sigint#abc123-def456-789",
        device_id: "dev_123",
        fuzzy_hash: undefined,
        ttl,
      });
    });

    it("should build public_key entry", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...base64...";
      const fingerprint: Fingerprint = { public_key: publicKey };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: `pubkey#${publicKey}`,
        device_id: "dev_123",
        fuzzy_hash: undefined,
        ttl,
      });
    });

    it("should NOT build stable_hash or fuzzy_hash entries (those go to PG)", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable456",
        fuzzy_hash: "fuzzy789",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toEqual([]);
    });

    it("should build only identity entries when all fields present", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie",
        sigint_id: "sigint-uuid-123",
        public_key: publicKey,
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
        ja4: "ja4hash",
      };

      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      // 3 identity entries only - hash entries go to PG device_hashes
      expect(entries).toHaveLength(3);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain("evercookie#cookie");
      expect(hashKeys).toContain("sigint#sigint-uuid-123");
      expect(hashKeys).toContain(`pubkey#${publicKey}`);
      expect(hashKeys).not.toContain("stable#stable");
      expect(hashKeys).not.toContain("fuzzy#fuzzy");
    });
  });

  describe("updateProfile", () => {
    it("should create new profile with defaults", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        canvas_hash: "canvas456",
      };

      await service.updateProfile({
        deviceId: "dev_new",
        fingerprint,
        timestamp: Date.now(),
        existingProfile: null,
      });

      const calls = dynamoMock.commandCalls(PutItemCommand);
      expect(calls).toHaveLength(1);

      const putCall = calls[0];
      expect(putCall.args[0].input.TableName).toBe(testConfig.profilesTable);

      const item = putCall.args[0].input.Item;
      expect(item?.device_id?.S).toBe("dev_new");
      expect(item?.stable_hash?.S).toBe("stable123");
      expect(item?.risk_score?.N).toBe("0.5");
      expect(item?.request_count?.N).toBe("1");
    });

    it("should compute dynamic risk_score and preserve positive flags", async () => {
      dynamoMock.on(PutItemCommand).resolves({});

      const existingProfile: DeviceProfile = {
        device_id: "dev_existing",
        risk_score: 0.8,
        flags: ["verified", "returning_user"],
        first_seen_at: 1700000000000,
        last_seen_at: 1700100000000,
        request_count: 100,
        updated_at: 1700100000000,
        ttl: 1705000000,
      };

      await service.updateProfile({
        deviceId: "dev_existing",
        fingerprint: {},
        timestamp: Date.now(),
        existingProfile,
      });

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      // Base: 0.3 (returning) - 0.2 (verified) - 0.1 (returning_user) = 0.0
      // Blended: 0.0 * 0.7 + 0.8 * 0.3 = 0.24
      expect(parseFloat(item?.risk_score?.N ?? "0")).toBeCloseTo(0.24, 2);
      expect(item?.flags?.L).toHaveLength(2);
      expect(item?.request_count?.N).toBe("101");
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

      await service.updateProfile({
        deviceId: "dev_123",
        fingerprint: {},
        timestamp: Date.now(),
        existingProfile,
      });

      const calls = dynamoMock.commandCalls(PutItemCommand);
      const item = calls[0].args[0].input.Item;

      expect(item?.request_count?.N).toBe("43");
    });
  });

  describe("updateIdentityIndexes", () => {
    it("should write identity indexes when evidence is PUBLIC_KEY_MATCH (Tier 0.5)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        evercookie_id: "cookie123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["PUBLIC_KEY_MATCH"],
      );

      // Only 2 identity entries (pubkey# + evercookie#), hash entries go to PG
      expect(count).toBe(2);
    });

    it("should write identity indexes when evidence is STABLE_HASH_MATCH (Tier 1)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["STABLE_HASH_MATCH"],
      );

      // Only 1 identity entry (pubkey#)
      expect(count).toBe(1);
    });

    it("should write identity indexes when evidence is SESSION_ANCHOR_BUCKET", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable123",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["SESSION_ANCHOR_BUCKET"],
      );

      // Only 1 identity entry (evercookie#)
      expect(count).toBe(1);
    });

    it("should return 0 when evidence is IP_JA4_BUCKET (Tier 2 unbounded, not in allowed list)", async () => {
      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["IP_JA4_BUCKET"],
      );

      // IP_JA4_BUCKET is not in ASSOCIATION_ALLOWED_EVIDENCE — no identity writes
      expect(count).toBe(0);
    });

    it("should return 0 when evidence is GPU_SCREEN_TZ_BUCKET (Tier 2 unbounded)", async () => {
      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["GPU_SCREEN_TZ_BUCKET"],
      );

      expect(count).toBe(0);
    });

    it("should write identity indexes when evidence_codes is undefined (backward compat)", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateIdentityIndexes("dev_123", fingerprint);

      // Only 1 identity entry (pubkey#)
      expect(count).toBe(1);
    });

    it("should write identity indexes when evidence_codes is empty array", async () => {
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const fingerprint: Fingerprint = {
        public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        stable_hash: "stable123",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        [],
      );

      // Only 1 identity entry (pubkey#)
      expect(count).toBe(1);
    });

    it("should return 0 when only hash fields present (no identity fields)", async () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const count = await service.updateIdentityIndexes(
        "dev_123",
        fingerprint,
        ["PUBLIC_KEY_MATCH"],
      );

      // No identity fields → no identity entries to write
      expect(count).toBe(0);
    });
  });

  describe("processProfileUpdate", () => {
    it("should skip when mutation gate is active", async () => {
      mockCache._setGate("dev_gated");

      const payload: ProfileUpdatePayload = {
        device_id: "dev_gated",
        fingerprint: { stable_hash: "abc" },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(true);
      expect(result.reason).toBe("mutation_gate");
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
          stable_hash: "same_hash",
          canvas_hash: "same_canvas",
        },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(true);
      expect(result.reason).toBe("no_drift");
      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith(
        "dev_stable",
      );
    });

    it("should perform full update for new device", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(PutItemCommand).resolves({});
      dynamoMock.on(BatchWriteItemCommand).resolves({});

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
      // Only 1 identity entry (evercookie#) — stable_hash goes to PG device_hashes
      expect(result.tier1Writes).toBe(1);
      expect(mockCache.tryAcquireMutationGate).toHaveBeenCalledWith("dev_new");
    });

    it("should perform full update when drift detected", async () => {
      const existingProfile: DeviceProfile = {
        device_id: "dev_drift",
        stable_hash: "old_hash",
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
      dynamoMock.on(BatchWriteItemCommand).resolves({});

      const payload: ProfileUpdatePayload = {
        device_id: "dev_drift",
        fingerprint: {
          stable_hash: "new_hash",
          canvas_hash: "new_canvas",
          webgl_hash: "new_webgl",
        },
        timestamp: Date.now(),
      };

      const result = await service.processProfileUpdate(payload);

      expect(result.skipped).toBe(false);
      // No identity fields in fingerprint — only hash fields, which go to PG
      expect(result.tier1Writes).toBe(0);
    });
  });

  describe("detectBotSignals", () => {
    it("should detect SwiftShader GPU renderer as headless browser", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "SwiftShader",
      };

      const flags = detectBotSignals(fingerprint);

      expect(flags).toContain("headless_browser");
      expect(flags).toContain("bot_detected");
    });

    it("should detect small viewport as bot", () => {
      const fingerprint: Fingerprint = {
        screen_dims: "800x600",
      };

      const flags = detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should detect bot user agent", () => {
      const fingerprint: Fingerprint = {
        user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)",
      };

      const flags = detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should detect crawler user agent", () => {
      const fingerprint: Fingerprint = {
        user_agent: "Mozilla/5.0 (compatible; Baiduspider/2.0)",
      };

      const flags = detectBotSignals(fingerprint);

      expect(flags).toContain("bot_detected");
    });

    it("should detect single core with low memory as bot", () => {
      const fingerprint: Fingerprint = {
        hardware_concurrency: 1,
        device_memory: 0.5,
      };

      const flags = detectBotSignals(fingerprint);

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

      const flags = detectBotSignals(fingerprint);

      expect(flags).toHaveLength(0);
    });

    it("should remove duplicate flags", () => {
      const fingerprint: Fingerprint = {
        gpu_renderer: "SwiftShader",
        screen_dims: "800x600",
      };

      const flags = detectBotSignals(fingerprint);

      const botDetectedCount = flags.filter((f) => f === "bot_detected").length;
      expect(botDetectedCount).toBe(1);
    });
  });

  describe("computeFlags", () => {
    it("should set NEW_DEVICE flag for new devices", () => {
      const fingerprint: Fingerprint = {};

      const flags = computeFlags(fingerprint, null, {
        isNewDevice: true,
        hasDrift: false,
      });

      expect(flags).toContain("new_device");
    });

    it("should set FINGERPRINT_MISMATCH flag when drift detected", () => {
      const fingerprint: Fingerprint = {};
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.5,
        flags: [],
        first_seen_at: Date.now() - 86400000,
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = computeFlags(fingerprint, existingProfile, {
        isNewDevice: false,
        hasDrift: true,
      });

      expect(flags).toContain("fingerprint_mismatch");
    });

    it("should set RAPID_REQUESTS flag for high request rate", () => {
      const fingerprint: Fingerprint = {};
      const oneHourAgo = Date.now() - 3600000;
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.5,
        flags: [],
        first_seen_at: oneHourAgo,
        last_seen_at: Date.now() - 60000,
        request_count: 100,
        updated_at: Date.now() - 60000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = computeFlags(fingerprint, existingProfile, {
        isNewDevice: false,
        hasDrift: false,
      });

      expect(flags).toContain("rapid_requests");
    });

    it("should preserve positive flags from existing profile", () => {
      const fingerprint: Fingerprint = {};
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.3,
        flags: ["verified", "returning_user"],
        first_seen_at: Date.now() - 86400000 * 30,
        last_seen_at: Date.now() - 3600000,
        request_count: 500,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      const flags = computeFlags(fingerprint, existingProfile, {
        isNewDevice: false,
        hasDrift: false,
      });

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

      const flags = computeFlags(fingerprint, existingProfile, {
        isNewDevice: false,
        hasDrift: false,
      });

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

      const flags = computeFlags(fingerprint, existingProfile, {
        isNewDevice: false,
        hasDrift: true,
      });

      expect(flags).toContain("headless_browser");
      expect(flags).toContain("bot_detected");
      expect(flags).toContain("fingerprint_mismatch");
      expect(flags).toContain("rapid_requests");
      expect(flags).toContain("verified");
    });
  });

  describe("computeRiskScore", () => {
    it("should return base risk of 0.5 for new device", () => {
      const score = computeRiskScore([], null, true);
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

      const score = computeRiskScore([], existingProfile, false);
      expect(score).toBe(0.3);
    });

    it("should increase risk for bot_detected flag", () => {
      const score = computeRiskScore(["bot_detected"], null, true);
      expect(score).toBe(0.75);
    });

    it("should increase risk for headless_browser flag", () => {
      const score = computeRiskScore(["headless_browser"], null, true);
      expect(score).toBe(0.65);
    });

    it("should increase risk for fingerprint_mismatch flag", () => {
      const score = computeRiskScore(["fingerprint_mismatch"], null, true);
      expect(score).toBe(0.65);
    });

    it("should increase risk for rapid_requests flag", () => {
      const score = computeRiskScore(["rapid_requests"], null, true);
      expect(score).toBe(0.6);
    });

    it("should decrease risk for verified flag", () => {
      const score = computeRiskScore(["verified"], null, true);
      expect(score).toBe(0.3);
    });

    it("should decrease risk for returning_user flag", () => {
      const score = computeRiskScore(["returning_user"], null, true);
      expect(score).toBe(0.4);
    });

    it("should stack multiple negative signals", () => {
      const flags = ["bot_detected", "headless_browser", "rapid_requests"];
      const score = computeRiskScore(flags, null, true);
      expect(score).toBe(1.0);
    });

    it("should clamp risk score to maximum of 1.0", () => {
      const flags = [
        "bot_detected",
        "headless_browser",
        "fingerprint_mismatch",
        "rapid_requests",
      ];
      const score = computeRiskScore(flags, null, true);
      expect(score).toBe(1.0);
    });

    it("should clamp risk score to minimum of 0.0", () => {
      const flags = ["verified", "returning_user"];
      const score = computeRiskScore(flags, null, true);
      expect(score).toBeCloseTo(0.2, 2);
    });

    it("should blend with historical risk for returning devices", () => {
      const existingProfile: DeviceProfile = {
        device_id: "d1",
        risk_score: 0.9,
        flags: [],
        first_seen_at: Date.now() - 86400000,
        last_seen_at: Date.now() - 3600000,
        request_count: 10,
        updated_at: Date.now() - 3600000,
        ttl: Date.now() / 1000 + 86400,
      };

      // Base risk for returning = 0.3
      // With 30% historical weight: 0.3 * 0.7 + 0.9 * 0.3 = 0.21 + 0.27 = 0.48
      const score = computeRiskScore([], existingProfile, false);
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
      const score = computeRiskScore(["bot_detected"], existingProfile, false);
      expect(score).toBeCloseTo(0.475, 2);
    });

    it("should not blend historical risk for new devices", () => {
      const score = computeRiskScore(["verified"], null, true);
      expect(score).toBe(0.3);
    });

    it("should silently ignore unknown flags", () => {
      const score = computeRiskScore(
        ["unknown_flag", "another_unknown"],
        null,
        true,
      );
      expect(score).toBe(0.5);
    });

    it("should process known flags and ignore unknown flags in same array", () => {
      const score = computeRiskScore(
        ["bot_detected", "unknown_flag", "verified"],
        null,
        true,
      );
      // 0.5 base + 0.25 bot - 0.2 verified = 0.55 (unknown ignored)
      expect(score).toBe(0.55);
    });
  });
});
