import { describe, it, expect, beforeEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
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
import {
  createFingerprint,
  createDriftedFingerprint,
  FingerprintPresets,
} from "../../../tests/utils";

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

  describe("Tier 1 matching", () => {
    it("should use Tier 1 match when stable_hash found", async () => {
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

      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        ip_address: "10.0.0.1",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.match_tier).toBe(1);
      expect(result.device_id).toBe("dev_tier1");
    });

    it("should create new device when no Tier 1 match found", async () => {
      dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const fingerprint: Fingerprint = {
        stable_hash: "unknown",
        ip_address: "10.0.0.1",
      };

      const { result } = await service.runTieredMatching(fingerprint);

      expect(result.is_new_device).toBe(true);
      expect(result.match_tier).toBe(-1);
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
  ];

  describe.each(signalCombinations)(
    "$name",
    ({ fingerprint, expectedTier, expectedConfidence, expectedEvidence }) => {
      it(`should match at tier ${expectedTier} with confidence ${expectedConfidence}`, async () => {
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

  describe("concurrent matches at different tiers", () => {
    it("should always prefer higher tier match", async () => {
      dynamoMock.on(GetItemCommand).callsFake(async (input) => {
        const key = input.Key?.hash_key?.S;

        if (key?.startsWith("evercookie#")) {
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

      expect(result.match_tier).toBe(0.5);
      expect(result.device_id).toBe("dev_evercookie");
    });
  });
});

describe("Using Fingerprint Factory Presets", () => {
  describe("FULL preset", () => {
    it("should have evercookie, stable_hash, fuzzy_hash, and fingerprint signals", () => {
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
  });

  describe("MINIMAL preset", () => {
    it("should only have stable_hash", () => {
      const fp = createFingerprint(FingerprintPresets.MINIMAL);

      expect(fp.stable_hash).toBeDefined();
      expect(fp.evercookie_id).toBeUndefined();
      expect(fp.fuzzy_hash).toBeUndefined();
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
      expect(fp.canvas_hash).toBeUndefined();
      expect(fp.audio_hash).toBeUndefined();
    });
  });
});
