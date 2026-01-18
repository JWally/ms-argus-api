// src/services/matching/matching-service.test.ts
// AR-52: Updated to use DynamoCacheService mock instead of Redis
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  BatchGetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  generateIdempotencyKey,
  generateULID,
} from "./matching-service";
import { EvidenceCode, Fingerprint, SessionCacheValue } from "./types";
import { DynamoCacheService } from "../cache";

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

// Mock DynamoCacheService for testing
function createMockCacheService() {
  const sessions = new Map<string, SessionCacheValue>();
  return {
    checkSessionCache: vi.fn().mockImplementation(async (sessionId: string) => {
      return sessions.get(sessionId) || null;
    }),
    writeSessionCache: vi
      .fn()
      .mockImplementation(
        async (sessionId: string, value: SessionCacheValue) => {
          // Simulate conditional write - only write if confidence is higher
          const existing = sessions.get(sessionId);
          if (
            !existing ||
            existing.confidence < value.confidence ||
            existing.status !== "complete"
          ) {
            sessions.set(sessionId, value);
          }
        },
      ),
    tryAcquireMutationGate: vi.fn().mockResolvedValue(true),
    // Helper for tests
    _setSession: (sessionId: string, value: SessionCacheValue) =>
      sessions.set(sessionId, value),
    _getSession: (sessionId: string) => sessions.get(sessionId),
    _clearSessions: () => sessions.clear(),
  } as unknown as DynamoCacheService & {
    _setSession: (sessionId: string, value: SessionCacheValue) => void;
    _getSession: (sessionId: string) => SessionCacheValue | undefined;
    _clearSessions: () => void;
  };
}

describe("MatchingService", () => {
  let dynamodb: DynamoDBClient;
  let sqs: SQSClient;
  let mockCache: ReturnType<typeof createMockCacheService>;
  let service: MatchingService;

  beforeEach(() => {
    // Reset mocks
    dynamoMock.reset();
    sqsMock.reset();

    // Create fresh cache mock
    mockCache = createMockCacheService();

    // Create real clients (mocked by aws-sdk-client-mock)
    dynamodb = new DynamoDBClient({});
    sqs = new SQSClient({});

    // Create service with test dependencies
    const deps: MatchingServiceDeps = {
      dynamodb,
      sqs,
      cache: mockCache,
      config: testConfig,
    };
    service = new MatchingService(deps);
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
        evidence_codes: ["STABLE_HASH_MATCH"],
        updated_at: Date.now(),
      };

      mockCache._setSession(sessionId, cachedValue);

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

      const result = await service.tier05CookieLookup("unknown-cookie");
      expect(result).toBeNull();
    });

    it("should return match result when evercookie found", async () => {
      const deviceId = "dev_existing";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "evercookie#cookie123",
          device_id: deviceId,
          risk_score: 0.2,
          flags: ["trusted"],
        }),
      });

      const result = await service.tier05CookieLookup("cookie123");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe(deviceId);
      expect(result?.confidence).toBe(0.99);
      expect(result?.match_tier).toBe(0.5);
      expect(result?.is_new_device).toBe(false);
      expect(result?.risk_score).toBe(0.2);
      expect(result?.flags).toEqual(["trusted"]);
      expect(result?.evidence_codes).toEqual(["EVERCOOKIE_MATCH"]);
    });

    it("should use default risk_score when not in index", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "evercookie#cookie123",
          device_id: "dev_123",
        }),
      });

      const result = await service.tier05CookieLookup("cookie123");
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  // AR-81: Sigint ID (third-party cookie) matching tests
  describe("tier05SigintIdLookup", () => {
    it("should return null when sigint_id not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.tier05SigintIdLookup("unknown-sigint-id");
      expect(result).toBeNull();
    });

    it("should return match result when sigint_id found", async () => {
      const deviceId = "dev_existing";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "sigint#abc123-def456",
          device_id: deviceId,
          risk_score: 0.2,
          flags: ["trusted"],
        }),
      });

      const result = await service.tier05SigintIdLookup("abc123-def456");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe(deviceId);
      expect(result?.confidence).toBe(0.98); // Slightly lower than evercookie
      expect(result?.match_tier).toBe(0.5);
      expect(result?.is_new_device).toBe(false);
      expect(result?.risk_score).toBe(0.2);
      expect(result?.flags).toEqual(["trusted"]);
      expect(result?.evidence_codes).toEqual(["SIGINT_ID_MATCH"]);
    });

    it("should use default risk_score when not in index", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "sigint#abc123",
          device_id: "dev_123",
        }),
      });

      const result = await service.tier05SigintIdLookup("abc123");
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  // AR-64: Public key (ECDSA) matching tests
  describe("tier05PublicKeyLookup", () => {
    it("should return null when public key not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.tier05PublicKeyLookup("unknown-public-key");
      expect(result).toBeNull();
    });

    it("should return match result when public key found", async () => {
      const deviceId = "dev_existing";
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...base64...";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: `pubkey#${publicKey}`,
          device_id: deviceId,
          risk_score: 0.2,
          flags: ["trusted"],
        }),
      });

      const result = await service.tier05PublicKeyLookup(publicKey);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe(deviceId);
      expect(result?.confidence).toBe(0.99);
      expect(result?.match_tier).toBe(0.5);
      expect(result?.is_new_device).toBe(false);
      expect(result?.risk_score).toBe(0.2);
      expect(result?.flags).toEqual(["trusted"]);
      expect(result?.evidence_codes).toEqual(["PUBLIC_KEY_MATCH"]);
    });

    it("should use default risk_score when not in index", async () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: `pubkey#${publicKey}`,
          device_id: "dev_123",
        }),
      });

      const result = await service.tier05PublicKeyLookup(publicKey);
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  describe("tier1HashMatch", () => {
    it("should return null when no hash matches", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const result = await service.tier1HashMatch(fingerprint);
      expect(result).toBeNull();
    });

    it("should match on stable_hash with 0.95 confidence", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "stable#stable123",
          device_id: "dev_stable",
          risk_score: 0.25,
        }),
      });

      const fingerprint: Fingerprint = { stable_hash: "stable123" };
      const result = await service.tier1HashMatch(fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_stable");
      expect(result?.confidence).toBe(0.95);
      expect(result?.match_tier).toBe(1);
      expect(result?.evidence_codes).toEqual(["STABLE_HASH_MATCH"]);
    });

    it("should match on fuzzy_hash with 0.85 confidence when stable_hash not found", async () => {
      dynamoMock
        .on(GetItemCommand, {
          TableName: testConfig.tier1IndexTable,
          Key: {
            hash_key: { S: "stable#stable123" },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
          TableName: testConfig.tier1IndexTable,
          Key: {
            hash_key: { S: "fuzzy#fuzzy456" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "fuzzy#fuzzy456",
            device_id: "dev_fuzzy",
          }),
        });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const result = await service.tier1HashMatch(fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_fuzzy");
      expect(result?.confidence).toBe(0.85);
      expect(result?.evidence_codes).toEqual(["FUZZY_HASH_MATCH"]);
    });

    it("should prefer stable_hash over fuzzy_hash when both available", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "stable#stable123",
          device_id: "dev_stable",
        }),
      });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const result = await service.tier1HashMatch(fingerprint);
      expect(result?.confidence).toBe(0.95); // stable_hash confidence
    });
  });

  // AR-119: buildBucketKeys tests moved to bucket-keys.test.ts (AR-117)
  // Deleted 10 duplicate tests that are now covered in src/helpers/bucket-keys.test.ts

  describe("tier2CompoundMatch", () => {
    it("should return null when no buckets match", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const result = await service.tier2CompoundMatch(fingerprint);
      expect(result).toBeNull();
    });

    it("should return null when only one bucket matches (need 2+)", async () => {
      // Only one bucket has the device (single Query returns items)
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({
            bucket_key: "ip_ja4#1.2.3.4#ja4hash",
            device_id: "dev_single",
          }),
        ],
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const result = await service.tier2CompoundMatch(fingerprint);
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

      const result = await service.tier2CompoundMatch(fingerprint);

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

      const { result, timedOut } =
        await service.tier2CompoundMatchWithTimeout(fingerprint);
      expect(result).toBeNull();
      expect(timedOut).toBe(true);
    });

    it("should return timedOut=false when matching completes in time", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
      };

      const { result, timedOut } =
        await service.tier2CompoundMatchWithTimeout(fingerprint);
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
      const result = await service.tier2CompoundMatch(fingerprint, {
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
      await expect(service.tier2CompoundMatch(fingerprint)).rejects.toThrow(
        "DynamoDB error",
      );
    });
  });

  // AR-56: Cardinality tracking tests
  describe("tier2CompoundMatch with cardinality tracking", () => {
    it("should penalize confidence for high-cardinality buckets", async () => {
      // Setup: device appears in 2 buckets (same device_id in all query results)
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [marshall({ device_id: "device-123" })],
        });

      // Mock cardinality stats - high cardinality buckets (>500)
      dynamoMock.on(BatchGetItemCommand).resolves({
        Responses: {
          [testConfig.tier2BucketsTable]: [
            marshall({
              bucket_key: "ip_ja4#1.2.3.4#ja4hash",
              cardinality: 1000,
            }),
            marshall({
              bucket_key: "gpu_screen_tz#GPU#1920x1080#America/New_York",
              cardinality: 800,
            }),
          ],
        },
      });

      // Mock profile lookup
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({ risk_score: 0.4, flags: [] }),
        });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "America/New_York",
      };

      const result = await service.tier2CompoundMatch(fingerprint);

      expect(result).not.toBeNull();
      expect(result?.match_tier).toBe(2);
      // Base confidence for 2 bucket matches is 0.8
      // With both buckets being high-cardinality: penalty = (2/2) * 0.3 = 0.3
      // Final confidence = 0.8 - 0.3 = 0.5
      expect(result?.confidence).toBeLessThan(0.8);
      expect(result?.confidence).toBeGreaterThanOrEqual(0.3);
    });

    it("should not penalize confidence for low-cardinality buckets", async () => {
      // Setup: device appears in 2 buckets
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [marshall({ device_id: "device-123" })],
        });

      // Mock cardinality stats - low cardinality buckets (<500)
      dynamoMock.on(BatchGetItemCommand).resolves({
        Responses: {
          [testConfig.tier2BucketsTable]: [
            marshall({
              bucket_key: "ip_ja4#1.2.3.4#ja4hash",
              cardinality: 50,
            }),
            marshall({
              bucket_key: "gpu_screen_tz#GPU#1920x1080#America/New_York",
              cardinality: 100,
            }),
          ],
        },
      });

      // Mock profile lookup
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({ risk_score: 0.4, flags: [] }),
        });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "America/New_York",
      };

      const result = await service.tier2CompoundMatch(fingerprint);

      expect(result).not.toBeNull();
      expect(result?.match_tier).toBe(2);
      // Base confidence for 2 bucket matches is 0.8 (no penalty applied)
      expect(result?.confidence).toBe(0.8);
    });

    it("should fail open when cardinality fetch fails", async () => {
      // Setup: device appears in 2 buckets
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [marshall({ device_id: "device-123" })],
        });

      // Mock cardinality fetch to fail
      dynamoMock.on(BatchGetItemCommand).rejects(new Error("DynamoDB error"));

      // Mock profile lookup
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({ risk_score: 0.4, flags: [] }),
        });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "America/New_York",
      };

      // Should not throw, should return match without penalty
      const result = await service.tier2CompoundMatch(fingerprint);

      expect(result).not.toBeNull();
      expect(result?.match_tier).toBe(2);
      // No penalty applied when cardinality fetch fails (fail open)
      expect(result?.confidence).toBe(0.8);
    });
  });

  describe("loadProfile", () => {
    it("should return null when profile not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await service.loadProfile("unknown-device");
      expect(result).toBeNull();
    });

    it("should return profile with risk_score and flags", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          device_id: "dev_123",
          risk_score: 0.7,
          flags: ["bot_detected", "vpn"],
        }),
      });

      const result = await service.loadProfile("dev_123");

      expect(result).not.toBeNull();
      expect(result?.risk_score).toBe(0.7);
      expect(result?.flags).toEqual(["bot_detected", "vpn"]);
    });
  });

  describe("createNewDevice", () => {
    // AR-121: Updated to expect ULID format (26 alphanumeric chars in Crockford's Base32)
    it("should create device with dev_ prefix and ULID format", () => {
      const result = service.createNewDevice();

      // ULID format: 26 characters, Crockford's Base32 (0-9, A-Z excluding I, L, O, U)
      expect(result.device_id).toMatch(/^dev_[0-9A-HJKMNP-TV-Z]{26}$/);
      expect(result.is_new_device).toBe(true);
      expect(result.confidence).toBe(0); // AR-55: No match confidence for new devices
      expect(result.match_tier).toBe(-1);
      expect(result.risk_score).toBe(0.5);
      expect(result.flags).toEqual([]);
    });

    it("should include NEW_DEVICE evidence code", () => {
      const result = service.createNewDevice();
      expect(result.evidence_codes).toEqual(["NEW_DEVICE"]);
    });

    it("should generate unique device IDs", () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(service.createNewDevice().device_id);
      }
      expect(ids.size).toBe(100);
    });
  });

  // AR-65: Privacy browser penalty tests
  describe("applyPrivacyPenalty", () => {
    it("should return unchanged result when no privacy signals", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = { stable_hash: "abc" };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBe(0.95);
      expect(penalized).toBe(result); // Same object reference
    });

    it("should reduce confidence for privacy_browser", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = {
        stable_hash: "abc",
        privacy_browser: "brave",
      };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBeCloseTo(0.8, 10); // 0.95 - 0.15 penalty
      expect(penalized).not.toBe(result); // New object
    });

    it("should reduce confidence for is_private_browsing", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = {
        stable_hash: "abc",
        is_private_browsing: true,
      };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBeCloseTo(0.85, 10); // 0.95 - 0.1 penalty
    });

    it("should apply cumulative penalties for both signals", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = {
        stable_hash: "abc",
        privacy_browser: "tor",
        is_private_browsing: true,
      };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBeCloseTo(0.7, 10); // 0.95 - 0.15 - 0.1 = 0.7
    });

    it("should not reduce confidence below 0", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.1,
        match_tier: 2,
        is_new_device: false,
        risk_score: 0.5,
        flags: [] as string[],
        evidence_codes: [
          "IP_JA4_BUCKET",
          "GPU_SCREEN_TZ_BUCKET",
        ] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = {
        privacy_browser: "firefox_rfp",
        is_private_browsing: true,
      };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBe(0); // Clamped at 0, not negative
    });
  });

  describe("runTieredMatching", () => {
    // AR-64: Public key matching tests
    it("should return public_key match at Tier 0.5", async () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...base64...";
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: `pubkey#${publicKey}`,
          device_id: "dev_pubkey",
        }),
      });

      const fingerprint: Fingerprint = { public_key: publicKey };
      const { result, tier2TimedOut } =
        await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_pubkey");
      expect(result.evidence_codes).toEqual(["PUBLIC_KEY_MATCH"]);
      expect(tier2TimedOut).toBe(false);
    });

    it("should prefer public_key over evercookie (both present)", async () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...base64...";
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: `pubkey#${publicKey}` },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: `pubkey#${publicKey}`,
            device_id: "dev_pubkey",
          }),
        })
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "evercookie#cookie123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "evercookie#cookie123",
            device_id: "dev_cookie",
          }),
        });

      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
      };
      const { result } = await service.runTieredMatching(fingerprint);

      // Public key should take precedence
      expect(result.device_id).toBe("dev_pubkey");
      expect(result.evidence_codes).toEqual(["PUBLIC_KEY_MATCH"]);
    });

    it("should fall back to evercookie when public_key not found", async () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...unknown...";
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: `pubkey#${publicKey}` },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "evercookie#cookie123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "evercookie#cookie123",
            device_id: "dev_cookie",
          }),
        });

      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
      };
      const { result } = await service.runTieredMatching(fingerprint);

      // Should fall back to evercookie
      expect(result.device_id).toBe("dev_cookie");
      expect(result.evidence_codes).toEqual(["EVERCOOKIE_MATCH"]);
    });

    it("should return evercookie match at Tier 0.5", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "evercookie#cookie123",
          device_id: "dev_cookie",
        }),
      });

      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const { result, tier2TimedOut } =
        await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_cookie");
      expect(tier2TimedOut).toBe(false);
    });

    // AR-65: Privacy penalty integration test
    it("should apply privacy browser penalty to match results", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_key: "evercookie#cookie123",
          device_id: "dev_cookie",
        }),
      });

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        privacy_browser: "brave",
        is_private_browsing: true,
      };
      const { result } = await service.runTieredMatching(fingerprint);

      // Base confidence is 0.99, minus 0.15 for privacy_browser, minus 0.1 for private_browsing
      expect(result.confidence).toBeCloseTo(0.74, 10);
    });

    it("should fall through to Tier 1 when evercookie not found", async () => {
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "evercookie#cookie123" },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable456" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable456",
            device_id: "dev_stable",
          }),
        });

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable456",
      };

      const { result } = await service.runTieredMatching(fingerprint);
      expect(result.match_tier).toBe(1);
    });

    it("should create new device when all tiers fail", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        stable_hash: "unknown",
      };

      const { result, tier2TimedOut } =
        await service.runTieredMatching(fingerprint);

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

      const { result, tier2TimedOut } =
        await service.runTieredMatching(fingerprint);

      expect(result.is_new_device).toBe(true);
      expect(tier2TimedOut).toBe(true);
    });
  });

  describe("writeMatchResult", () => {
    it("should write result to cache", async () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      await service.writeMatchResult("session123", result, "idempkey");

      // Verify cache service was called
      expect(mockCache.writeSessionCache).toHaveBeenCalledWith(
        "session123",
        expect.objectContaining({
          status: "complete",
          device_id: "dev_123",
          confidence: 0.95,
          evidence_codes: ["STABLE_HASH_MATCH"],
        }),
      );

      // Verify value was written
      const value = mockCache._getSession("session123");
      expect(value).not.toBeUndefined();
      expect(value?.status).toBe("complete");
      expect(value?.device_id).toBe("dev_123");
      expect(value?.confidence).toBe(0.95);
      expect(value?.evidence_codes).toEqual(["STABLE_HASH_MATCH"]);
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
        evidence_codes: ["EVERCOOKIE_MATCH"],
        updated_at: Date.now(),
      };
      mockCache._setSession("session123", existing);

      // Try to write lower confidence match
      const result = {
        device_id: "dev_worse",
        confidence: 0.85,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.5,
        flags: [] as string[],
        evidence_codes: ["FUZZY_HASH_MATCH"] as EvidenceCode[],
      };

      await service.writeMatchResult("session123", result, "newkey");

      // Should still have the better match (mock simulates conditional write)
      const value = mockCache._getSession("session123");
      expect(value?.device_id).toBe("dev_better");
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
        evidence_codes: ["IP_JA4_BUCKET", "GPU_SCREEN_TZ_BUCKET"],
        updated_at: Date.now(),
      };
      mockCache._setSession("session123", existing);

      // Write higher confidence match
      const result = {
        device_id: "dev_better",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      await service.writeMatchResult("session123", result, "newkey");

      const value = mockCache._getSession("session123");
      expect(value?.device_id).toBe("dev_better");
    });
  });

  describe("writeDegradedResult", () => {
    it("should write degraded status to cache", async () => {
      await service.writeDegradedResult("session123", "idempkey");

      // Verify cache service was called
      expect(mockCache.writeSessionCache).toHaveBeenCalledWith(
        "session123",
        expect.objectContaining({
          status: "degraded",
          device_id: "",
          flags: ["matching_failed"],
        }),
      );

      const value = mockCache._getSession("session123");
      expect(value).not.toBeUndefined();
      expect(value?.status).toBe("degraded");
      expect(value?.device_id).toBe("");
      expect(value?.flags).toContain("matching_failed");
    });
  });

  describe("queueProfileUpdate", () => {
    it("should send message to SQS profile queue", async () => {
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg123" });

      const payload = {
        session_id: "session123",
        fingerprint: { stable_hash: "abc" },
        tcp_blob: "encrypted",
        tls_blob: "encrypted",
        headers: {},
        timestamp: Date.now(),
      };

      await service.queueProfileUpdate("dev_123", payload);

      const calls = sqsMock.calls();
      expect(calls).toHaveLength(1);

      const call = calls[0];
      const input = call.args[0].input as {
        QueueUrl: string;
        MessageBody: string;
      };
      expect(input.QueueUrl).toBe(testConfig.profileQueueUrl);

      const messageBody = JSON.parse(input.MessageBody);
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

// AR-121: Tests updated for ULID format
describe("generateULID", () => {
  it("should generate valid ULID format (26 chars, Crockford Base32)", () => {
    const ulid = generateULID();
    // ULID: 26 characters, Crockford's Base32 (0-9, A-Z excluding I, L, O, U)
    expect(ulid).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("should generate unique ULIDs", () => {
    const ulids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ulids.add(generateULID());
    }
    expect(ulids.size).toBe(1000);
  });

  it("should produce no collisions in 100K generated ULIDs", () => {
    const ulids = new Set<string>();
    const count = 100_000;
    for (let i = 0; i < count; i++) {
      const ulid = generateULID();
      expect(ulids.has(ulid)).toBe(false);
      ulids.add(ulid);
    }
    expect(ulids.size).toBe(count);
  }, 30000); // 30 second timeout for 100K iterations

  it("should generate ULIDs with timestamp prefix for time-based sorting", () => {
    // ULIDs have a 48-bit timestamp in first 10 characters
    // The timestamp encodes milliseconds since Unix epoch in Crockford Base32
    // ULIDs generated at different times will sort chronologically
    const ulid1 = generateULID();
    const ulid2 = generateULID();

    // Both should be valid ULID format
    expect(ulid1).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(ulid2).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);

    // First 10 chars are timestamp - ULIDs from same ms share this prefix
    // This proves the time component is encoded at the start
    const timestamp1 = ulid1.substring(0, 10);
    const timestamp2 = ulid2.substring(0, 10);

    // ULIDs generated in sequence will have same or later timestamp
    // (later timestamp is lexicographically greater)
    expect(timestamp2 >= timestamp1).toBe(true);
  });
});

// AR-95: Anchor lookup recency sorting tests
describe("MatchingService anchor recency sorting", () => {
  let dynamodb: DynamoDBClient;
  let sqs: SQSClient;
  let mockCache: ReturnType<typeof createMockCacheService>;
  let service: MatchingService;

  beforeEach(() => {
    dynamoMock.reset();
    sqsMock.reset();
    mockCache = createMockCacheService();
    dynamodb = new DynamoDBClient({});
    sqs = new SQSClient({});

    const deps: MatchingServiceDeps = {
      dynamodb,
      sqs,
      cache: mockCache,
      config: testConfig,
    };
    service = new MatchingService(deps);
  });

  it("should return most recent valid device, not first alphabetically", async () => {
    const now = Date.now();

    // Mock: Multiple devices in same anchor bucket
    // DynamoDB returns items sorted by device_id (sort key) alphabetically
    // dev_aaa is OLDER but comes first alphabetically
    // dev_zzz is NEWER but comes last alphabetically
    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        // Session anchor query - return items sorted by device_id (DynamoDB default)
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              // First alphabetically, but OLDER (5 minutes ago - still valid for 10min window)
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_aaa_old",
                created_at: now - 5 * 60 * 1000, // 5 minutes ago
              }),
              // Second alphabetically, but NEWER (1 minute ago)
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_zzz_new",
                created_at: now - 1 * 60 * 1000, // 1 minute ago
              }),
            ],
          };
        }
        return { Items: [] };
      });

    // Mock: Profile lookup for the expected device
    dynamoMock.on(GetItemCommand).resolves({
      Item: marshall({
        device_id: "dev_zzz_new",
        risk_score: 0.3,
        flags: [],
      }),
    });

    // Fingerprint with no tier0.5/tier1 matches - will fall through to anchor lookup
    const fingerprint: Fingerprint = {
      ip_address: "1.2.3.4",
      user_agent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
      screen_dims: "1920x1080",
    };

    const { result } = await service.runTieredMatching(fingerprint);

    // AR-95: Should return the MOST RECENT valid device (dev_zzz_new),
    // NOT the first alphabetically (dev_aaa_old)
    expect(result.device_id).toBe("dev_zzz_new");
    expect(result.evidence_codes).toContain("SESSION_ANCHOR_BUCKET");
  });

  it("should skip expired devices even if they are more recent", async () => {
    const now = Date.now();

    // Mock: One expired device (newer) and one valid device (older)
    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              // First alphabetically, EXPIRED (created 15 mins ago, validity is 10 mins)
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_aaa_expired",
                created_at: now - 15 * 60 * 1000, // 15 minutes ago - EXPIRED
              }),
              // Second alphabetically, VALID but older within window
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_bbb_valid",
                created_at: now - 8 * 60 * 1000, // 8 minutes ago - still valid
              }),
            ],
          };
        }
        return { Items: [] };
      });

    // Mock: Profile lookup
    dynamoMock.on(GetItemCommand).resolves({
      Item: marshall({
        device_id: "dev_bbb_valid",
        risk_score: 0.3,
        flags: [],
      }),
    });

    const fingerprint: Fingerprint = {
      ip_address: "1.2.3.4",
      user_agent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
      screen_dims: "1920x1080",
    };

    const { result } = await service.runTieredMatching(fingerprint);

    // Should return the valid device, not the expired one
    expect(result.device_id).toBe("dev_bbb_valid");
  });

  it("should prefer most recent among multiple valid devices", async () => {
    const now = Date.now();

    // Mock: Three valid devices with different ages
    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              // Alphabetically first, 7 minutes old
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_a",
                created_at: now - 7 * 60 * 1000,
              }),
              // Alphabetically middle, 3 minutes old (NEWEST)
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_m",
                created_at: now - 3 * 60 * 1000,
              }),
              // Alphabetically last, 5 minutes old
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_z",
                created_at: now - 5 * 60 * 1000,
              }),
            ],
          };
        }
        return { Items: [] };
      });

    // Mock: Profile lookup for expected device
    dynamoMock.on(GetItemCommand).resolves({
      Item: marshall({
        device_id: "dev_m",
        risk_score: 0.3,
        flags: [],
      }),
    });

    const fingerprint: Fingerprint = {
      ip_address: "1.2.3.4",
      user_agent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
      screen_dims: "1920x1080",
    };

    const { result } = await service.runTieredMatching(fingerprint);

    // Should return dev_m (3 minutes old) - the newest valid device
    expect(result.device_id).toBe("dev_m");
  });

  // AR-121: Test that ScanIndexForward:false is used for anchor queries
  it("should pass ScanIndexForward:false to sessionAnchorLookup QueryCommand", async () => {
    const now = Date.now();
    let capturedInput: unknown;

    // Mock: Capture the QueryCommand input to verify ScanIndexForward
    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        capturedInput = input;
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_test",
                created_at: now - 1 * 60 * 1000,
              }),
            ],
          };
        }
        return { Items: [] };
      });

    // Mock: Profile lookup
    dynamoMock.on(GetItemCommand).resolves({
      Item: marshall({
        device_id: "dev_test",
        risk_score: 0.3,
        flags: [],
      }),
    });

    const fingerprint: Fingerprint = {
      ip_address: "1.2.3.4",
      user_agent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
      screen_dims: "1920x1080",
    };

    await service.runTieredMatching(fingerprint);

    // AR-121: Verify ScanIndexForward:false is set
    expect(capturedInput).toHaveProperty("ScanIndexForward", false);
  });
});
