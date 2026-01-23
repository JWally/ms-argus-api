// src/services/matching/matching-permutations.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  BatchGetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient } from "@aws-sdk/client-sqs";
import { marshall } from "@aws-sdk/util-dynamodb";
import {
  MatchingService,
  MatchingServiceConfig,
  MatchingServiceDeps,
} from "./matching-service";
import { Fingerprint, SessionCacheValue } from "./types";
import { DynamoCacheService } from "../cache";
import { buildBucketKeys } from "../../helpers/bucket-keys";
import {
  createFingerprint,
  createDriftedFingerprint,
  FingerprintPresets,
} from "../../../tests/utils";

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

// Mock DynamoCacheService
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

describe("Tier Priority Tests", () => {
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

  describe("evercookie vs stable_hash priority", () => {
    it("should use Tier 0.5 (evercookie) when both evercookie and stable_hash match", async () => {
      // Both evercookie and stable_hash return valid matches
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "evercookie#cookie123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "evercookie#cookie123",
            device_id: "dev_evercookie",
            risk_score: 0.1,
          }),
        })
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable456" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable456",
            device_id: "dev_stable",
            risk_score: 0.2,
          }),
        });

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable456",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_evercookie");
      expect(result.confidence).toBe(0.99);
      expect(result.evidence_codes).toContain("EVERCOOKIE_MATCH");
    });

    it("should fall back to Tier 1 (stable_hash) when evercookie not found", async () => {
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
      expect(result.device_id).toBe("dev_stable");
      expect(result.confidence).toBe(0.95);
      expect(result.evidence_codes).toContain("STABLE_HASH_MATCH");
    });
  });

  describe("stable_hash vs fuzzy_hash priority", () => {
    it("should use stable_hash when both stable_hash and fuzzy_hash match", async () => {
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable123",
            device_id: "dev_stable",
          }),
        })
        .on(GetItemCommand, {
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

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(1);
      expect(result.device_id).toBe("dev_stable");
      expect(result.confidence).toBe(0.95);
      expect(result.evidence_codes).toContain("STABLE_HASH_MATCH");
    });

    it("should use fuzzy_hash when stable_hash not found", async () => {
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable123" },
          },
        })
        .resolves({ Item: undefined })
        .on(GetItemCommand, {
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

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(1);
      expect(result.device_id).toBe("dev_fuzzy");
      expect(result.confidence).toBe(0.85);
      expect(result.evidence_codes).toContain("FUZZY_HASH_MATCH");
    });
  });

  describe("Tier 1 vs Tier 2 priority", () => {
    it("should use Tier 1 match over Tier 2 match", async () => {
      // Tier 1 stable_hash matches
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable123",
            device_id: "dev_tier1",
          }),
        });

      // Tier 2 buckets would also match if we got there
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [marshall({ device_id: "dev_tier2" })],
        });

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        audio_hash: "audio123",
        canvas_hash: "canvas456",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(1);
      expect(result.device_id).toBe("dev_tier1");
    });

    it("should use Tier 2 match when Tier 1 not found", async () => {
      // Tier 1 doesn't match
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      // Tier 2 buckets match
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [marshall({ device_id: "dev_tier2" })],
        });

      // Cardinality lookup
      dynamoMock.on(BatchGetItemCommand).resolves({
        Responses: {
          [testConfig.tier2BucketsTable]: [],
        },
      });

      // Profile lookup for Tier 2 device
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({
            device_id: "dev_tier2",
            risk_score: 0.4,
            flags: [],
          }),
        });

      const fingerprint: Fingerprint = {
        stable_hash: "unknown",
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        audio_hash: "audio123",
        canvas_hash: "canvas456",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(2);
      expect(result.device_id).toBe("dev_tier2");
    });
  });
});

describe("Signal Presence Matrix", () => {
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

  // Table-driven tests for signal combinations
  const signalCombinations = [
    {
      name: "evercookie only",
      fingerprint: { evercookie_id: "ev123" },
      expectedTier: 0.5,
      expectedConfidence: 0.99,
      expectedEvidence: "EVERCOOKIE_MATCH",
    },
    {
      name: "stable_hash only",
      fingerprint: { stable_hash: "stable123" },
      expectedTier: 1,
      expectedConfidence: 0.95,
      expectedEvidence: "STABLE_HASH_MATCH",
    },
    {
      name: "fuzzy_hash only",
      fingerprint: { fuzzy_hash: "fuzzy123" },
      expectedTier: 1,
      expectedConfidence: 0.85,
      expectedEvidence: "FUZZY_HASH_MATCH",
    },
    {
      name: "all tier 1 signals",
      fingerprint: {
        evercookie_id: "ev123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy123",
      },
      expectedTier: 0.5,
      expectedConfidence: 0.99,
      expectedEvidence: "EVERCOOKIE_MATCH",
    },
    {
      name: "tier 2 signals only (2 compound buckets)",
      fingerprint: {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        audio_hash: "audio",
        canvas_hash: "canvas",
      },
      expectedTier: 2,
      expectedConfidence: 0.8, // 2 buckets = 0.8 confidence
      expectedEvidence: "IP_JA4_BUCKET",
      needsTier2Match: true,
    },
    {
      name: "tier 2 signals only (all 3 compound buckets)",
      fingerprint: {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "UTC",
        audio_hash: "audio",
        canvas_hash: "canvas",
      },
      expectedTier: 2,
      expectedConfidence: 0.85, // 3 buckets = max confidence
      expectedEvidence: "IP_JA4_BUCKET",
      needsTier2Match: true,
    },
  ];

  describe.each(signalCombinations)(
    "$name",
    ({
      fingerprint,
      expectedTier,
      expectedConfidence,
      expectedEvidence,
      needsTier2Match,
    }) => {
      it(`should match at tier ${expectedTier} with confidence ${expectedConfidence}`, async () => {
        // Setup mocks based on fingerprint content
        if (fingerprint.evercookie_id) {
          dynamoMock
            .on(GetItemCommand, {
              Key: {
                hash_key: { S: `evercookie#${fingerprint.evercookie_id}` },
              },
            })
            .resolves({
              Item: marshall({
                hash_key: `evercookie#${fingerprint.evercookie_id}`,
                device_id: "dev_match",
                risk_score: 0.3,
              }),
            });
        }

        if (fingerprint.stable_hash && expectedTier !== 0.5) {
          dynamoMock
            .on(GetItemCommand, {
              Key: {
                hash_key: { S: `stable#${fingerprint.stable_hash}` },
              },
            })
            .resolves({
              Item: marshall({
                hash_key: `stable#${fingerprint.stable_hash}`,
                device_id: "dev_match",
                risk_score: 0.3,
              }),
            });
        }

        if (
          fingerprint.fuzzy_hash &&
          expectedTier !== 0.5 &&
          expectedEvidence === "FUZZY_HASH_MATCH"
        ) {
          // Only mock fuzzy if it's the expected match
          dynamoMock
            .on(GetItemCommand, {
              Key: {
                hash_key: { S: `fuzzy#${fingerprint.fuzzy_hash}` },
              },
            })
            .resolves({
              Item: marshall({
                hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
                device_id: "dev_match",
                risk_score: 0.3,
              }),
            });
        }

        if (needsTier2Match) {
          // No tier 1 matches
          dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

          // Tier 2 bucket matches
          dynamoMock
            .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
            .resolves({
              Items: [marshall({ device_id: "dev_match" })],
            });

          // Cardinality lookup (low cardinality = no penalty)
          dynamoMock.on(BatchGetItemCommand).resolves({
            Responses: {
              [testConfig.tier2BucketsTable]: [],
            },
          });

          // Profile lookup
          dynamoMock
            .on(GetItemCommand, { TableName: testConfig.profilesTable })
            .resolves({
              Item: marshall({
                device_id: "dev_match",
                risk_score: 0.3,
                flags: [],
              }),
            });
        }

        const { result } = await service.runTieredMatching(
          fingerprint as Fingerprint,
        );

        expect(result.match_tier).toBe(expectedTier);
        expect(result.confidence).toBeCloseTo(expectedConfidence, 1);
        expect(result.evidence_codes).toContain(expectedEvidence);
      });
    },
  );

  describe("no signals present", () => {
    it("should create new device when fingerprint is empty", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {};

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.is_new_device).toBe(true);
      expect(result.match_tier).toBe(-1);
      expect(result.confidence).toBe(0);
      expect(result.evidence_codes).toContain("NEW_DEVICE");
    });
  });

  describe("partial signals", () => {
    it("should not build ip_ja4 bucket when only ip_address present", () => {
      const fingerprint: Fingerprint = { ip_address: "10.0.0.1" };
      const keys = buildBucketKeys(fingerprint);
      expect(keys).toHaveLength(0);
    });

    it("should not build gpu_screen_tz bucket when only gpu_renderer present", () => {
      const fingerprint: Fingerprint = { gpu_renderer: "GPU" };
      const keys = buildBucketKeys(fingerprint);
      expect(keys).toHaveLength(0);
    });

    it("should not build audio_canvas bucket when only audio_hash present", () => {
      const fingerprint: Fingerprint = { audio_hash: "audio123" };
      const keys = buildBucketKeys(fingerprint);
      expect(keys).toHaveLength(0);
    });
  });
});

describe("Fingerprint Drift Scenarios", () => {
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

  describe("device with changing IP address", () => {
    it("should still match via stable_hash when IP changes", async () => {
      const original = createFingerprint({
        includeStableHash: true,
        includeIpJa4: true,
        stableHash: "stable-device-123",
      });

      const drifted = createDriftedFingerprint(original, { changeIp: true });

      // Stable hash still matches
      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable-device-123" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable-device-123",
            device_id: "dev_original",
          }),
        });

      const { result } = await service.runTieredMatching(drifted);

      expect(result.device_id).toBe("dev_original");
      expect(result.match_tier).toBe(1);
    });
  });

  describe("device with changing screen resolution", () => {
    it("should still match via stable_hash when screen dims change", async () => {
      const original = createFingerprint({
        includeStableHash: true,
        includeGpuScreenTz: true,
        stableHash: "stable-device-456",
      });

      const drifted = createDriftedFingerprint(original, {
        changeScreen: true,
      });

      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable-device-456" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable-device-456",
            device_id: "dev_original",
          }),
        });

      const { result } = await service.runTieredMatching(drifted);

      expect(result.device_id).toBe("dev_original");
      expect(result.match_tier).toBe(1);
    });
  });

  describe("device with changing timezone", () => {
    it("should still match via stable_hash when timezone changes (travel)", async () => {
      const original = createFingerprint({
        includeStableHash: true,
        includeGpuScreenTz: true,
        stableHash: "stable-traveler",
      });

      const drifted = createDriftedFingerprint(original, {
        changeTimezone: true,
      });

      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable-traveler" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable-traveler",
            device_id: "dev_traveler",
          }),
        });

      const { result } = await service.runTieredMatching(drifted);

      expect(result.device_id).toBe("dev_traveler");
      expect(result.match_tier).toBe(1);
    });
  });

  describe("device with user agent update (browser update)", () => {
    it("should still match via stable_hash when user agent changes", async () => {
      const original = createFingerprint({
        includeStableHash: true,
        includeBotSignals: true,
        stableHash: "stable-browser-user",
      });

      const drifted = createDriftedFingerprint(original, {
        changeUserAgent: true,
      });

      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: "stable#stable-browser-user" },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: "stable#stable-browser-user",
            device_id: "dev_browser",
          }),
        });

      const { result } = await service.runTieredMatching(drifted);

      expect(result.device_id).toBe("dev_browser");
    });
  });

  describe("complete fingerprint drift", () => {
    it("should create new device when all tier 2 signals change and no tier 1 match", async () => {
      const original = createFingerprint(FingerprintPresets.TIER2_ONLY);
      const drifted = createDriftedFingerprint(original, {
        changeIp: true,
        changeScreen: true,
        changeTimezone: true,
      });

      // No tier 1 or tier 2 matches
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const { result } = await service.runTieredMatching(drifted);

      expect(result.is_new_device).toBe(true);
      expect(result.match_tier).toBe(-1);
    });
  });
});

describe("Edge Cases", () => {
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

  describe("empty fingerprint", () => {
    it("should create new device with NEW_DEVICE evidence code", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const { result } = await service.runTieredMatching({});

      expect(result.is_new_device).toBe(true);
      expect(result.evidence_codes).toEqual(["NEW_DEVICE"]);
      expect(result.risk_score).toBe(0.5);
    });
  });

  describe("whitespace and empty string handling", () => {
    it("should treat empty strings as absent signals", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        stable_hash: "",
        fuzzy_hash: "",
        evercookie_id: "",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.is_new_device).toBe(true);
    });

    it("should not build bucket keys for empty string signals", () => {
      const fingerprint: Fingerprint = {
        ip_address: "",
        ja4: "",
        gpu_renderer: "",
        screen_dims: "",
        timezone: "",
      };

      const keys = buildBucketKeys(fingerprint);
      expect(keys).toHaveLength(0);
    });
  });

  describe("very long hash values", () => {
    it("should handle long stable_hash values", async () => {
      const longHash = "a".repeat(256);

      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: `stable#${longHash}` },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: `stable#${longHash}`,
            device_id: "dev_long",
          }),
        });

      const fingerprint: Fingerprint = { stable_hash: longHash };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.device_id).toBe("dev_long");
    });
  });

  describe("special characters in signals", () => {
    it("should handle special characters in hash values", async () => {
      const specialHash = "abc#123$def%456";

      dynamoMock
        .on(GetItemCommand, {
          Key: {
            hash_key: { S: `stable#${specialHash}` },
          },
        })
        .resolves({
          Item: marshall({
            hash_key: `stable#${specialHash}`,
            device_id: "dev_special",
          }),
        });

      const fingerprint: Fingerprint = { stable_hash: specialHash };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.device_id).toBe("dev_special");
    });
  });

  describe("multiple devices in same bucket", () => {
    it("should select device with most bucket overlap", async () => {
      // No tier 1 matches
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });

      // Multiple devices in buckets - dev_winner appears in all 3, dev_partial in 1
      dynamoMock
        .on(QueryCommand, { TableName: testConfig.tier2BucketsTable })
        .resolves({
          Items: [
            marshall({ device_id: "dev_winner" }),
            marshall({ device_id: "dev_partial" }),
          ],
        });

      // Low cardinality
      dynamoMock.on(BatchGetItemCommand).resolves({
        Responses: {
          [testConfig.tier2BucketsTable]: [],
        },
      });

      // Profile lookup (returns first device found with most overlap)
      dynamoMock
        .on(GetItemCommand, { TableName: testConfig.profilesTable })
        .resolves({
          Item: marshall({
            device_id: "dev_winner",
            risk_score: 0.3,
            flags: [],
          }),
        });

      const fingerprint: Fingerprint = {
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
        gpu_renderer: "GPU",
        screen_dims: "1920x1080",
        timezone: "UTC",
        audio_hash: "audio",
        canvas_hash: "canvas",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(2);
      // The device with most bucket appearances should be selected
    });
  });

  describe("concurrent matches at different tiers", () => {
    it("should always prefer higher tier match", async () => {
      // Simulate race condition where tier 2 might return first
      // but tier 0.5 evercookie should still win

      dynamoMock.on(GetItemCommand).callsFake(async (input) => {
        const key = input.Key?.hash_key?.S;

        if (key?.startsWith("evercookie#")) {
          // Evercookie lookup is slow but returns
          await new Promise((resolve) => setTimeout(resolve, 50));
          return {
            Item: marshall({
              hash_key: key,
              device_id: "dev_evercookie",
            }),
          };
        }
        return { Item: undefined };
      });

      dynamoMock.on(QueryCommand).resolves({
        Items: [marshall({ device_id: "dev_tier2" })],
      });

      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        ip_address: "10.0.0.1",
        ja4: "ja4hash",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      // Even though tier 2 might have been faster, evercookie should win
      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_evercookie");
    });
  });
});

describe("Using Fingerprint Factory Presets", () => {
  describe("FULL preset", () => {
    it("should have evercookie, stable_hash, fuzzy_hash, and all tier 2 signals", () => {
      const fp = createFingerprint(FingerprintPresets.FULL);

      expect(fp.evercookie_id).toBeDefined();
      expect(fp.stable_hash).toBeDefined();
      expect(fp.fuzzy_hash).toBeDefined();
      expect(fp.ip_address).toBeDefined();
      expect(fp.ja4).toBeDefined();
      expect(fp.gpu_renderer).toBeDefined();
      expect(fp.screen_dims).toBeDefined();
      expect(fp.timezone).toBeDefined();
      expect(fp.audio_hash).toBeDefined();
      expect(fp.canvas_hash).toBeDefined();
    });

    it("should build all 3 bucket keys", () => {
      const fp = createFingerprint(FingerprintPresets.FULL);
      const keys = buildBucketKeys(fp);
      expect(keys).toHaveLength(3);
    });
  });

  describe("MINIMAL preset", () => {
    it("should only have stable_hash", () => {
      const fp = createFingerprint(FingerprintPresets.MINIMAL);

      expect(fp.stable_hash).toBeDefined();
      expect(fp.evercookie_id).toBeUndefined();
      expect(fp.fuzzy_hash).toBeUndefined();
    });

    it("should build no bucket keys", () => {
      const fp = createFingerprint(FingerprintPresets.MINIMAL);
      const keys = buildBucketKeys(fp);
      expect(keys).toHaveLength(0);
    });
  });

  describe("BOT_LIKE preset", () => {
    it("should have bot-like characteristics", () => {
      const fp = createFingerprint(FingerprintPresets.BOT_LIKE);

      expect(fp.hardware_concurrency).toBe(1);
      expect(fp.device_memory).toBe(0);
      expect(fp.user_agent).toBe("HeadlessChrome");
    });
  });

  describe("MOBILE preset", () => {
    it("should have mobile characteristics", () => {
      const fp = createFingerprint(FingerprintPresets.MOBILE);

      expect(fp.screen_dims).toBe("390x844");
      expect(fp.device_memory).toBe(4);
      expect(fp.hardware_concurrency).toBe(6);
    });
  });

  describe("PRIVACY_BROWSER preset", () => {
    it("should have limited signals (privacy browsers block canvas/audio)", () => {
      const fp = createFingerprint(FingerprintPresets.PRIVACY_BROWSER);

      expect(fp.stable_hash).toBeDefined();
      expect(fp.ip_address).toBeDefined();
      expect(fp.ja4).toBeDefined();
      // Canvas and audio typically blocked
      expect(fp.canvas_hash).toBeUndefined();
      expect(fp.audio_hash).toBeUndefined();
    });
  });
});
