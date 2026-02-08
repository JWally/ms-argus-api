import { describe, it, expect, vi, beforeEach } from "vitest";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { publicKeyLookup, cookieLookup, sigintIdLookup } from "./index-lookup";

vi.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: vi.fn(),
  GetItemCommand: vi.fn(),
}));

describe("fuzzy_match_info drift detection", () => {
  let mockDynamodb: DynamoDBClient;
  const tier1IndexTable = "test-tier1-index";

  beforeEach(() => {
    vi.clearAllMocks();
    mockDynamodb = new DynamoDBClient({});
  });

  describe("publicKeyLookup", () => {
    it("should include fuzzy_match_info when both hashes are present", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
          fuzzy_hash: { S: "0123456789abcdef" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await publicKeyLookup(
        deps,
        "pubkey123",
        "0123456789abcdef",
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
      const result = await publicKeyLookup(
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
      const result = await publicKeyLookup(deps, "pubkey123");

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeUndefined();
    });

    it("should not include fuzzy_match_info when stored hash is missing", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_123" },
          risk_score: { N: "0.3" },
          flags: { L: [] },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await publicKeyLookup(
        deps,
        "pubkey123",
        "0123456789abcdef",
      );

      expect(result).not.toBeNull();
      expect(result!.fuzzy_match_info).toBeUndefined();
    });
  });

  describe("cookieLookup", () => {
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
      const result = await cookieLookup(deps, "cookie123", "fedcba9876543210");

      expect(result).not.toBeNull();
      expect(result!.evidence_codes).toContain("EVERCOOKIE_MATCH");
      expect(result!.fuzzy_match_info).toBeDefined();
      expect(result!.fuzzy_match_info!.hamming_distance).toBe(0);
    });
  });

  describe("sigintIdLookup", () => {
    it("should include fuzzy_match_info for sigint match", async () => {
      mockDynamodb.send = vi.fn().mockResolvedValue({
        Item: {
          device_id: { S: "dev_789" },
          risk_score: { N: "0.25" },
          flags: { L: [] },
          fuzzy_hash: { S: "abcd1234efgh5678" },
        },
      });

      const deps = { dynamodb: mockDynamodb, tier1IndexTable };
      const result = await sigintIdLookup(
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
});
