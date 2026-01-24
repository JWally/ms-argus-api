// src/services/matching/fuzzy-match-info.test.ts
// AR-XXX: Tests for fuzzy_match_info drift detection feature

import { describe, it, expect, vi, beforeEach } from "vitest";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  tier05PublicKeyLookup,
  tier05CookieLookup,
  tier05SigintIdLookup,
} from "./tier05-identity";
import { tier1HashMatch } from "./tier1-hash";

// Mock DynamoDB
vi.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: vi.fn(),
  GetItemCommand: vi.fn(),
}));

describe("AR-XXX: fuzzy_match_info drift detection", () => {
  let mockDynamodb: DynamoDBClient;
  const tier1IndexTable = "test-tier1-index";

  beforeEach(() => {
    vi.clearAllMocks();
    mockDynamodb = new DynamoDBClient({});
  });

  describe("tier05PublicKeyLookup", () => {
    it("should include fuzzy_match_info when both hashes are present", async () => {
      // Mock DynamoDB to return a device with fuzzy_hash
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "0123456789abcdef" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await tier05PublicKeyLookup(
        deps,
        "pubkey123",
        "0123456789abcdef", // Same hash = distance 0
      );

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.incoming_hash).toBe("0123456789abcdef");
      expect(result!.fuzzy_match_info!.stored_hash).toBe("0123456789abcdef");
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(0);
      expect(result!.fuzzy_match_info!.similarity).toBe(1);
    });

    it("should compute correct hamming distance for different hashes", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "0000000000000000" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      // 000f = 4 bits set (1111 in binary)
      const result = await tier05PublicKeyLookup(
        deps,
        "pubkey123",
        "000f000000000000",
      );

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(4);
      expect(result!.fuzzy_match_info!.similarity).toBeCloseTo(1 - 4 / 64, 5);
    });

    it("should not include fuzzy_match_info when incoming hash is missing", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "0123456789abcdef" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await tier05PublicKeyLookup(deps, "pubkey123");

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeUndefined();
    });

    it("should not include fuzzy_match_info when stored hash is missing", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          // No fuzzy_hash stored
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await tier05PublicKeyLookup(
        deps,
        "pubkey123",
        "0123456789abcdef",
      );

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeUndefined();
    });
  });

  describe("tier05CookieLookup", () => {
    it("should include fuzzy_match_info for evercookie match", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_456" },
          risk_score: { N: "0.2" },
          flags: { L: [] },
          fuzzy_hash: { S: "fedcba9876543210" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await tier05CookieLookup(
        deps,
        "cookie123",
        "fedcba9876543210",
      );

      expect(result).not.toBeNull();
      expect(result!.evidence_codes).toContain("EVERCOOKIE_MATCH");
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(0);
    });
  });

  describe("tier05SigintIdLookup", () => {
    it("should include fuzzy_match_info for sigint match", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_789" },
          risk_score: { N: "0.25" },
          flags: { L: [] },
          fuzzy_hash: { S: "abcd1234efgh5678" }, // Invalid hex - should return -1 distance
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      // Pass valid hex
      const result = await tier05SigintIdLookup(
        deps,
        "sigint-id",
        "1111111111111111",
      );

      expect(result).not.toBeNull();
      expect(result!.evidence_codes).toContain("SIGINT_ID_MATCH");
      // fuzzy_match_info should have -1 distance for invalid stored hash
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(-1);
    });
  });

  describe("tier1HashMatch", () => {
    it("should include fuzzy_match_info for stable_hash match", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_stable" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "aaaaaaaaaaaaaaaa" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "aaaaaaaaaaaaaaaa",
      };
      const result = await tier1HashMatch(deps, fingerprint);

      expect(result).not.toBeNull();
      expect(result!.evidence_codes).toContain("STABLE_HASH_MATCH");
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(0);
      expect(result!.fuzzy_match_info!.similarity).toBe(1);
    });

    it("should include fuzzy_match_info for fuzzy_hash match", async () => {
      // First call for stable# - not found
      // Second call for fuzzy# - found
      mockDynamodb.send = vi
        .fn()
        .mockResolvedValueOnce({}) // stable# not found
        .mockResolvedValueOnce({
          Item: {
            device_id: { S: "dev_fuzzy" },
            risk_score: { N: "0.35" },
            flags: { L: [] },
            fuzzy_hash: { S: "bbbbbbbbbbbbbbbb" },
          },
        });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "bbbbbbbbbbbbbbbb",
      };
      const result = await tier1HashMatch(deps, fingerprint);

      expect(result).not.toBeNull();
      expect(result!.evidence_codes).toContain("FUZZY_HASH_MATCH");
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(0);
    });

    it("should detect drift when fuzzy hashes differ", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_drift" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "0000000000000000" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      // ffff = 16 bits set
      const fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "ffff000000000000",
      };
      const result = await tier1HashMatch(deps, fingerprint);

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(16);
      expect(result!.fuzzy_match_info!.similarity).toBeCloseTo(1 - 16 / 64, 5);
    });
  });
});
