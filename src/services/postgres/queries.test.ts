import { describe, it, expect, vi, beforeEach } from "vitest";
import { pgUnifiedMatch, pgUpsertDeviceHashes } from "./queries";
import { MatchTier } from "../../types/matching-tiers";

const mockPool = {
  query: vi.fn(),
};

describe("pgUnifiedMatch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return null when both hashes are missing", async () => {
    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: undefined,
        fuzzy_hash: undefined,
      } as any,
    );
    expect(result).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  it("should return null when fuzzy_hash is invalid and no stable_hash", async () => {
    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: undefined,
        fuzzy_hash: "not-a-valid-hex",
      } as any,
    );
    expect(result).toBeNull();
  });

  it("should return null when query returns no rows", async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: undefined,
      } as any,
    );
    expect(result).toBeNull();
  });

  it("should return stable hash match result for exact match", async () => {
    mockPool.query.mockResolvedValue({
      rows: [
        {
          device_id: "dev_001",
          stable_hash: "hash-abc",
          fuzzy_hash: null,
          last_seen: new Date(),
          exact_match: true,
          band_matches: 0,
        },
      ],
    });

    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: "a".repeat(64),
      } as any,
    );

    expect(result).not.toBeNull();
    expect(result!.match_tier).toBe(MatchTier.HASH);
    expect(result!.confidence).toBe(0.95);
    expect(result!.device_id).toBe("dev_001");
    expect(result!.evidence_codes).toContain("STABLE_HASH_MATCH");
  });

  it("should return simhash match for fuzzy candidate with low hamming distance", async () => {
    // Use a valid 64-char hex fuzzy hash
    const fuzzyHex = "a".repeat(64);
    // Convert to a BIT(256) string of all 1010...
    const fuzzyBitStr = fuzzyHex
      .split("")
      .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
      .join("");

    mockPool.query.mockResolvedValue({
      rows: [
        {
          device_id: "dev_002",
          stable_hash: "other-hash",
          fuzzy_hash: fuzzyBitStr, // same hash → hamming distance 0
          last_seen: new Date(),
          exact_match: false,
          band_matches: 16,
        },
      ],
    });

    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: fuzzyHex,
      } as any,
    );

    expect(result).not.toBeNull();
    expect(result!.match_tier).toBe(MatchTier.SIMHASH);
    expect(result!.device_id).toBe("dev_002");
    expect(result!.evidence_codes).toContain("SIMHASH_MATCH");
  });

  it("should return null when normalizedFuzzy is null and no stable match in rows", async () => {
    mockPool.query.mockResolvedValue({
      rows: [
        {
          device_id: "dev_001",
          stable_hash: "other-hash",
          fuzzy_hash: null,
          last_seen: new Date(),
          exact_match: false,
          band_matches: 5,
        },
      ],
    });

    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: undefined,
      } as any,
    );

    expect(result).toBeNull();
  });

  it("should skip candidates with no fuzzy_hash", async () => {
    const fuzzyHex = "b".repeat(64);

    mockPool.query.mockResolvedValue({
      rows: [
        {
          device_id: "dev_no_fuzzy",
          stable_hash: "other",
          fuzzy_hash: null, // no fuzzy hash
          last_seen: new Date(),
          exact_match: false,
          band_matches: 5,
        },
      ],
    });

    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: fuzzyHex,
      } as any,
    );

    expect(result).toBeNull();
  });

  it("should use zero bands when fuzzy hash is null", async () => {
    mockPool.query.mockResolvedValue({ rows: [] });

    await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: undefined,
      } as any,
    );

    // Verify query was called with null bands (16 zero-padded bit strings)
    const callArgs = mockPool.query.mock.calls[0][1];
    expect(callArgs[0]).toBe("hash-abc"); // stable_hash
    // Bands should be zero-padded 16-bit strings
    expect(callArgs[1]).toBe("0000000000000000");
  });

  it("should prefer stable hash match over simhash when both present", async () => {
    const fuzzyHex = "a".repeat(64);
    const fuzzyBitStr = fuzzyHex
      .split("")
      .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
      .join("");

    mockPool.query.mockResolvedValue({
      rows: [
        {
          device_id: "dev_stable",
          stable_hash: "hash-abc",
          fuzzy_hash: fuzzyBitStr,
          last_seen: new Date(),
          exact_match: true,
          band_matches: 16,
        },
        {
          device_id: "dev_fuzzy",
          stable_hash: "other",
          fuzzy_hash: fuzzyBitStr,
          last_seen: new Date(),
          exact_match: false,
          band_matches: 14,
        },
      ],
    });

    const result = await pgUnifiedMatch(
      mockPool as any,
      {
        stable_hash: "hash-abc",
        fuzzy_hash: fuzzyHex,
      } as any,
    );

    expect(result!.device_id).toBe("dev_stable");
    expect(result!.match_tier).toBe(MatchTier.HASH);
  });
});

describe("pgUpsertDeviceHashes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPool.query.mockResolvedValue({ rows: [] });
  });

  it("should upsert with stable hash only", async () => {
    await pgUpsertDeviceHashes(mockPool as any, {
      deviceId: "dev_001",
      stableHash: "hash-abc",
      lastSeen: 1704067200,
      expiresAt: 1709251200,
    });

    expect(mockPool.query).toHaveBeenCalledTimes(1);
    const args = mockPool.query.mock.calls[0][1];
    expect(args[0]).toBe("dev_001");
    expect(args[1]).toBe("hash-abc");
    expect(args[2]).toBeNull(); // fuzzyBits null
  });

  it("should upsert with valid fuzzy hash and compute bands", async () => {
    const validFuzzy = "a".repeat(64);
    await pgUpsertDeviceHashes(mockPool as any, {
      deviceId: "dev_001",
      stableHash: "hash-abc",
      fuzzyHash: validFuzzy,
      lastSeen: 1704067200,
      expiresAt: 1709251200,
    });

    const args = mockPool.query.mock.calls[0][1];
    expect(args[2]).not.toBeNull(); // fuzzyBits should be set
    // Band params should be 16-bit binary strings
    expect(args[3]).toHaveLength(16); // first band is 16 bits
  });

  it("should handle 0x prefix in fuzzy hash", async () => {
    const validFuzzy = "0x" + "b".repeat(64);
    await pgUpsertDeviceHashes(mockPool as any, {
      deviceId: "dev_001",
      fuzzyHash: validFuzzy,
      lastSeen: 1704067200,
      expiresAt: 1709251200,
    });

    const args = mockPool.query.mock.calls[0][1];
    expect(args[2]).not.toBeNull();
  });

  it("should warn and skip fuzzy hash if length is invalid", async () => {
    await pgUpsertDeviceHashes(mockPool as any, {
      deviceId: "dev_001",
      fuzzyHash: "abc", // too short
      lastSeen: 1704067200,
      expiresAt: 1709251200,
    });

    const args = mockPool.query.mock.calls[0][1];
    expect(args[2]).toBeNull(); // fuzzyBits should be null
  });

  it("should pass null for stableHash when not provided", async () => {
    await pgUpsertDeviceHashes(mockPool as any, {
      deviceId: "dev_001",
      lastSeen: 1704067200,
      expiresAt: 1709251200,
    });

    const args = mockPool.query.mock.calls[0][1];
    expect(args[1]).toBeNull();
  });
});
