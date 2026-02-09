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
import { createFingerprint, FingerprintPresets } from "../../../tests/utils";

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
