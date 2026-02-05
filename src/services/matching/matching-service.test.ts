import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
  generateIdempotencyKey,
} from "./matching-service";
import {
  publicKeyLookup,
  cookieLookup,
  sigintIdLookup,
  hashMatch,
  simHashMatch,
  sessionAnchorLookup,
  ipUaAnchorLookup,
  loadProfile,
  type IndexLookupDeps,
  type SimHashMatchDeps,
  type SessionAnchorDeps,
  type ProfileLoaderDeps,
} from ".";
import { EvidenceCode, Fingerprint, SessionCacheValue } from "./types";
import { DynamoCacheService } from "../cache";

const dynamoMock = mockClient(DynamoDBClient);
const sqsMock = mockClient(SQSClient);

const testConfig: MatchingServiceConfig = {
  tier1IndexTable: "test-tier1-index",
  tier2BucketsTable: "test-tier2-buckets",
  profilesTable: "test-profiles",
  profileQueueUrl: "https://sqs.us-east-1.amazonaws.com/123456789/test-queue",
  sessionTtlSeconds: 900,
  tier2TimeoutMs: 100,
};

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
          // Only write if confidence is higher (conditional write simulation)
          const existing = sessions.get(sessionId);
          if (
            !existing ||
            existing.confidence < value.confidence ||
            existing.status !== "complete"
          ) {
            sessions.set(sessionId, value);
            return true;
          }
          return false;
        },
      ),
    tryAcquireMutationGate: vi.fn().mockResolvedValue(true),
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
  let indexLookupDeps: IndexLookupDeps;
  let _simHashDeps: SimHashMatchDeps;
  let _anchorDeps: SessionAnchorDeps;
  let profileDeps: ProfileLoaderDeps;

  beforeEach(() => {
    dynamoMock.reset();
    sqsMock.reset();

    mockCache = createMockCacheService();

    dynamodb = new DynamoDBClient({});
    sqs = new SQSClient({});

    indexLookupDeps = { dynamodb, tier1IndexTable: testConfig.tier1IndexTable };
    _simHashDeps = {
      dynamodb,
      tier2BucketsTable: testConfig.tier2BucketsTable,
    };
    _anchorDeps = {
      dynamodb,
      tier2BucketsTable: testConfig.tier2BucketsTable,
      profilesTable: testConfig.profilesTable,
    };
    profileDeps = { dynamodb, profilesTable: testConfig.profilesTable };

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
      const result = await service.cache.checkSessionCache("unknown-session");
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

      const result = await service.cache.checkSessionCache(sessionId);
      expect(result).not.toBeNull();
      expect(result?.status).toBe("complete");
      expect(result?.device_id).toBe("dev_123");
      expect(result?.confidence).toBe(0.95);
    });
  });

  describe("cookieLookup", () => {
    it("should return null when evercookie not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await cookieLookup(indexLookupDeps, "unknown-cookie");
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

      const result = await cookieLookup(indexLookupDeps, "cookie123");

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

      const result = await cookieLookup(indexLookupDeps, "cookie123");
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  describe("sigintIdLookup", () => {
    it("should return null when sigint_id not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await sigintIdLookup(indexLookupDeps, "unknown-sigint-id");
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

      const result = await sigintIdLookup(indexLookupDeps, "abc123-def456");

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe(deviceId);
      expect(result?.confidence).toBe(0.98);
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

      const result = await sigintIdLookup(indexLookupDeps, "abc123");
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  describe("publicKeyLookup", () => {
    it("should return null when public key not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await publicKeyLookup(
        indexLookupDeps,
        "unknown-public-key",
      );
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

      const result = await publicKeyLookup(indexLookupDeps, publicKey);

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

      const result = await publicKeyLookup(indexLookupDeps, publicKey);
      expect(result?.risk_score).toBe(0.3);
      expect(result?.flags).toEqual([]);
    });
  });

  describe("hashMatch", () => {
    it("should return null when no hash matches", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };

      const result = await hashMatch(indexLookupDeps, fingerprint);
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
      const result = await hashMatch(indexLookupDeps, fingerprint);

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

      const result = await hashMatch(indexLookupDeps, fingerprint);

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

      const result = await hashMatch(indexLookupDeps, fingerprint);
      expect(result?.confidence).toBe(0.95);
    });
  });

  describe("loadProfile", () => {
    it("should return null when profile not found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      const result = await loadProfile(profileDeps, "unknown-device");
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

      const result = await loadProfile(profileDeps, "dev_123");

      expect(result).not.toBeNull();
      expect(result?.risk_score).toBe(0.7);
      expect(result?.flags).toEqual(["bot_detected", "vpn"]);
    });
  });

  describe("createNewDevice", () => {
    it("should create device with dev_ prefix and ULID format", () => {
      const result = service.createNewDevice();

      expect(result.device_id).toMatch(/^dev_[0-9A-HJKMNP-TV-Z]{26}$/);
      expect(result.is_new_device).toBe(true);
      expect(result.confidence).toBe(0);
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
      expect(penalized).toBe(result);
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

      expect(penalized.confidence).toBeCloseTo(0.8, 10);
      expect(penalized).not.toBe(result);
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

      expect(penalized.confidence).toBeCloseTo(0.85, 10);
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

      expect(penalized.confidence).toBeCloseTo(0.7, 10);
    });

    it("should not reduce confidence below 0", () => {
      const result = {
        device_id: "dev_123",
        confidence: 0.1,
        match_tier: 2,
        is_new_device: false,
        risk_score: 0.5,
        flags: [] as string[],
        evidence_codes: ["VECTOR_SIMILARITY"] as EvidenceCode[],
      };

      const fingerprint: Fingerprint = {
        privacy_browser: "firefox_rfp",
        is_private_browsing: true,
      };
      const penalized = service.applyPrivacyPenalty(result, fingerprint);

      expect(penalized.confidence).toBe(0);
    });
  });

  describe("runTieredMatching", () => {
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

    it("should match via ipUaAnchor when session anchor misses", async () => {
      const now = Date.now();

      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      dynamoMock.on(QueryCommand).callsFake((input) => {
        const exprValues = input.ExpressionAttributeValues;
        const bucketKey = exprValues?.[":bk"]?.S ?? "";
        if (bucketKey.startsWith("ip_ua_anchor#")) {
          return {
            Items: [
              marshall({
                bucket_key: bucketKey,
                device_id: "dev_ip_ua",
                created_at: now - 30 * 1000,
              }),
            ],
          };
        }
        return { Items: [] };
      });

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        user_agent: "Mozilla/5.0 Chrome/120",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.device_id).toBe("dev_ip_ua");
      expect(result.evidence_codes).toContain("IP_UA_ANCHOR_BUCKET");
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

      await service.writeMatchResult({
        sessionId: "session123",
        result,
        idempotencyKey: "idempkey",
      });

      expect(mockCache.writeSessionCache).toHaveBeenCalledWith(
        "session123",
        expect.objectContaining({
          status: "complete",
          device_id: "dev_123",
          confidence: 0.95,
          evidence_codes: ["STABLE_HASH_MATCH"],
        }),
      );

      const value = mockCache._getSession("session123");
      expect(value).not.toBeUndefined();
      expect(value?.status).toBe("complete");
      expect(value?.device_id).toBe("dev_123");
      expect(value?.confidence).toBe(0.95);
      expect(value?.evidence_codes).toEqual(["STABLE_HASH_MATCH"]);
    });

    it("should not overwrite higher confidence match", async () => {
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

      const result = {
        device_id: "dev_worse",
        confidence: 0.85,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.5,
        flags: [] as string[],
        evidence_codes: ["FUZZY_HASH_MATCH"] as EvidenceCode[],
      };

      await service.writeMatchResult({
        sessionId: "session123",
        result,
        idempotencyKey: "newkey",
      });

      const value = mockCache._getSession("session123");
      expect(value?.device_id).toBe("dev_better");
    });

    it("should overwrite lower confidence match", async () => {
      const existing: SessionCacheValue = {
        status: "complete",
        device_id: "dev_old",
        risk_score: 0.5,
        confidence: 0.7,
        match_tier: 2,
        match_version: Date.now(),
        idempotency_key: "old",
        flags: [],
        evidence_codes: ["VECTOR_SIMILARITY"],
        updated_at: Date.now(),
      };
      mockCache._setSession("session123", existing);

      const result = {
        device_id: "dev_better",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [] as string[],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };

      await service.writeMatchResult({
        sessionId: "session123",
        result,
        idempotencyKey: "newkey",
      });

      const value = mockCache._getSession("session123");
      expect(value?.device_id).toBe("dev_better");
    });
  });

  describe("writeDegradedResult", () => {
    it("should write degraded status to cache", async () => {
      await service.writeDegradedResult("session123", "idempkey");

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

    it("should include match_tier and evidence_codes when matchResult is provided", async () => {
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg123" });

      const payload = {
        session_id: "session123",
        fingerprint: { stable_hash: "abc" },
        tcp_blob: "encrypted",
        tls_blob: "encrypted",
        headers: {},
        timestamp: Date.now(),
      };

      const matchResult = {
        device_id: "dev_123",
        confidence: 0.95,
        match_tier: 0.5,
        is_new_device: false,
        risk_score: 0.1,
        flags: [],
        evidence_codes: ["PUBLIC_KEY_MATCH"] as EvidenceCode[],
      };

      await service.queueProfileUpdate("dev_123", payload, false, matchResult);

      const calls = sqsMock.calls();
      expect(calls).toHaveLength(1);

      const call = calls[0];
      const input = call.args[0].input as {
        QueueUrl: string;
        MessageBody: string;
      };
      const messageBody = JSON.parse(input.MessageBody);

      expect(messageBody.match_tier).toBe(0.5);
      expect(messageBody.evidence_codes).toEqual(["PUBLIC_KEY_MATCH"]);
    });

    it("should include multiple evidence codes when present", async () => {
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg123" });

      const payload = {
        session_id: "session123",
        fingerprint: { stable_hash: "abc" },
        headers: {},
        timestamp: Date.now(),
      };

      const matchResult = {
        device_id: "dev_123",
        confidence: 0.9,
        match_tier: 2,
        is_new_device: false,
        risk_score: 0.3,
        flags: [],
        evidence_codes: [
          "VECTOR_SIMILARITY",
          "HIGH_SIMILARITY",
        ] as EvidenceCode[],
      };

      await service.queueProfileUpdate("dev_123", payload, false, matchResult);

      const calls = sqsMock.calls();
      const input = calls[0].args[0].input as {
        QueueUrl: string;
        MessageBody: string;
      };
      const messageBody = JSON.parse(input.MessageBody);

      expect(messageBody.match_tier).toBe(2);
      expect(messageBody.evidence_codes).toHaveLength(2);
      expect(messageBody.evidence_codes).toContain("VECTOR_SIMILARITY");
    });

    it("should work without matchResult for backward compatibility", async () => {
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg123" });

      const payload = {
        session_id: "session123",
        fingerprint: { stable_hash: "abc" },
        headers: {},
        timestamp: Date.now(),
      };

      await service.queueProfileUpdate("dev_123", payload);

      const calls = sqsMock.calls();
      expect(calls).toHaveLength(1);

      const input = calls[0].args[0].input as {
        QueueUrl: string;
        MessageBody: string;
      };
      const messageBody = JSON.parse(input.MessageBody);

      expect(messageBody.device_id).toBe("dev_123");
      expect(messageBody.match_tier).toBeUndefined();
      expect(messageBody.evidence_codes).toBeUndefined();
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

describe("generateULID wrapper removed", () => {
  it("should not export generateULID from matching-service", async () => {
    const matchingService = await import("./matching-service");
    expect("generateULID" in matchingService).toBe(false);
  });

  it("createNewDevice should still generate valid dev_ prefixed ULID IDs", () => {
    const dynamodb = new DynamoDBClient({});
    const sqsClient = new SQSClient({});
    const mockCache = createMockCacheService();

    const deps: MatchingServiceDeps = {
      dynamodb,
      sqs: sqsClient,
      cache: mockCache,
      config: testConfig,
    };
    const svc = new MatchingService(deps);
    const result = svc.createNewDevice();

    expect(result.device_id).toMatch(/^dev_[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(result.is_new_device).toBe(true);
    expect(result.confidence).toBe(0);
    expect(result.match_tier).toBe(-1);
  });

  it("createNewDevice should produce unique IDs without generateULID wrapper", () => {
    const dynamodb = new DynamoDBClient({});
    const sqsClient = new SQSClient({});
    const mockCache = createMockCacheService();

    const deps: MatchingServiceDeps = {
      dynamodb,
      sqs: sqsClient,
      cache: mockCache,
      config: testConfig,
    };
    const svc = new MatchingService(deps);

    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(svc.createNewDevice().device_id);
    }
    expect(ids.size).toBe(100);
  });
});

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

    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_aaa_old",
                created_at: now - 5 * 60 * 1000,
              }),
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_zzz_new",
                created_at: now - 1 * 60 * 1000,
              }),
            ],
          };
        }
        return { Items: [] };
      });

    dynamoMock.on(GetItemCommand).resolves({
      Item: marshall({
        device_id: "dev_zzz_new",
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

    expect(result.device_id).toBe("dev_zzz_new");
    expect(result.evidence_codes).toContain("SESSION_ANCHOR_BUCKET");
  });

  it("should skip expired devices even if they are more recent", async () => {
    const now = Date.now();

    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_aaa_expired",
                created_at: now - 15 * 60 * 1000,
              }),
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_bbb_valid",
                created_at: now - 8 * 60 * 1000,
              }),
            ],
          };
        }
        return { Items: [] };
      });

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

    expect(result.device_id).toBe("dev_bbb_valid");
  });

  it("should prefer most recent among multiple valid devices", async () => {
    const now = Date.now();

    dynamoMock
      .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
      .callsFake((input) => {
        const keyExpr = input.KeyConditionExpression || "";
        if (keyExpr.includes("bucket_key = :bk")) {
          return {
            Items: [
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_a",
                created_at: now - 7 * 60 * 1000,
              }),
              marshall({
                bucket_key: "session_anchor#1.2.3.4#uahash#1920x1080",
                device_id: "dev_m",
                created_at: now - 3 * 60 * 1000,
              }),
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

    expect(result.device_id).toBe("dev_m");
  });

  it("should pass ScanIndexForward:false to sessionAnchorLookup QueryCommand", async () => {
    const now = Date.now();
    let capturedInput: unknown;

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

    expect(capturedInput).toHaveProperty("ScanIndexForward", false);
  });
});

describe("Tier function direct calls", () => {
  let dynamodb: DynamoDBClient;
  let simHashDeps: SimHashMatchDeps;
  let anchorDeps: SessionAnchorDeps;

  beforeEach(() => {
    dynamoMock.reset();
    sqsMock.reset();
    dynamodb = new DynamoDBClient({});
    simHashDeps = { dynamodb, tier2BucketsTable: testConfig.tier2BucketsTable };
    anchorDeps = {
      dynamodb,
      tier2BucketsTable: testConfig.tier2BucketsTable,
      profilesTable: testConfig.profilesTable,
    };
  });

  describe("simHashMatch", () => {
    it("should return null when no SimHash match found", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = { fuzzy_hash: "abcdef1234567890" };
      const result = await simHashMatch(simHashDeps, fingerprint);
      expect(result).toBeNull();
    });
  });

  describe("sessionAnchorLookup", () => {
    it("should return null when fingerprint lacks required fields", async () => {
      const fingerprint: Fingerprint = { ip_address: "1.2.3.4" };
      const result = await sessionAnchorLookup(anchorDeps, fingerprint);
      expect(result).toBeNull();
    });

    it("should return null when no items in bucket", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0 Chrome/120",
        screen_dims: "1920x1080",
      };
      const result = await sessionAnchorLookup(anchorDeps, fingerprint);
      expect(result).toBeNull();
    });

    it("should return match for recent entry within validity window", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({
            bucket_key: "session_anchor#1.2.3.4#hash#1920x1080",
            device_id: "dev_anchor",
            created_at: now - 2 * 60 * 1000,
          }),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          device_id: "dev_anchor",
          risk_score: 0.3,
          flags: [],
        }),
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0 Chrome/120",
        screen_dims: "1920x1080",
      };
      const result = await sessionAnchorLookup(anchorDeps, fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_anchor");
      expect(result?.evidence_codes).toContain("SESSION_ANCHOR_BUCKET");
    });
  });

  describe("ipUaAnchorLookup", () => {
    it("should return null when fingerprint lacks ip or user_agent", async () => {
      const fingerprint: Fingerprint = { ip_address: "1.2.3.4" };
      const result = await ipUaAnchorLookup(anchorDeps, fingerprint);
      expect(result).toBeNull();
    });

    it("should return null when no items in bucket", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0 Chrome/120",
      };
      const result = await ipUaAnchorLookup(anchorDeps, fingerprint);
      expect(result).toBeNull();
    });

    it("should return match for a recent entry within validity window", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({
            bucket_key: "ip_ua_anchor#1.2.3.4#hash",
            device_id: "dev_recent",
            created_at: now - 60 * 1000,
          }),
        ],
      });
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          device_id: "dev_recent",
          risk_score: 0.25,
          flags: ["returning_user"],
        }),
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0 Chrome/120",
      };
      const result = await ipUaAnchorLookup(anchorDeps, fingerprint);

      expect(result).not.toBeNull();
      expect(result?.device_id).toBe("dev_recent");
      expect(result?.confidence).toBe(0.6);
      expect(result?.evidence_codes).toContain("IP_UA_ANCHOR_BUCKET");
    });

    it("should return null when all entries are expired", async () => {
      const now = Date.now();
      dynamoMock.on(QueryCommand).resolves({
        Items: [
          marshall({
            bucket_key: "ip_ua_anchor#1.2.3.4#hash",
            device_id: "dev_old",
            created_at: now - 10 * 60 * 1000,
          }),
        ],
      });

      const fingerprint: Fingerprint = {
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0 Chrome/120",
      };
      const result = await ipUaAnchorLookup(anchorDeps, fingerprint);
      expect(result).toBeNull();
    });
  });
});
