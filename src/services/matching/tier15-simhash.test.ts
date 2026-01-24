import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { tier15SimHashMatch, Tier15SimHashDeps } from "./tier15-simhash";
import type { Fingerprint } from "../../types";

const dynamoMock = mockClient(DynamoDBClient);

const originalEnv = process.env;

function setSimHashEnv(overrides: Record<string, string> = {}) {
  process.env = {
    ...originalEnv,
    SIMHASH_ENABLED: "true",
    SIMHASH_SHADOW: "false",
    SIMHASH_ROLLOUT: "100",
    SIMHASH_LATENCY_BYPASS: "5000",
    POWERTOOLS_SERVICE_NAME: "argus-test",
    POWERTOOLS_METRICS_NAMESPACE: "ArgusTest",
    ...overrides,
  };
}

function createDeps(): Tier15SimHashDeps {
  return {
    dynamodb: new DynamoDBClient({}),
    tier2BucketsTable: "test-tier2-buckets",
  };
}

function createFingerprint(overrides: Partial<Fingerprint> = {}): Fingerprint {
  return {
    stable_hash: "abc123",
    fuzzy_hash: "1234567890abcdef",
    ...overrides,
  };
}

/**
 * Build a DynamoDB item for a band query result.
 * The device_id field uses the SK format: t#<inverted_ts>#<device_id>
 */
function buildBandItem(
  deviceId: string,
  fuzzyHash: string,
  lastSeen: number = Math.floor(Date.now() / 1000),
) {
  const invertedTs = (9999999999999 - lastSeen).toString().padStart(13, "0");
  return marshall({
    device_id: `t#${invertedTs}#${deviceId}`,
    fuzzy_hash: fuzzyHash,
    last_seen: lastSeen,
  });
}

describe("tier15SimHashMatch", () => {
  beforeEach(() => {
    dynamoMock.reset();
    setSimHashEnv();
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe("Feature Flags", () => {
    it("returns null when SIMHASH_ENABLED is false", async () => {
      setSimHashEnv({ SIMHASH_ENABLED: "false" });
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("returns null when rollout percentage excludes this hash", async () => {
      setSimHashEnv({ SIMHASH_ROLLOUT: "0" });
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("proceeds when rollout percentage includes this hash", async () => {
      setSimHashEnv({ SIMHASH_ROLLOUT: "100" });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("returns null in shadow mode even with a match", async () => {
      setSimHashEnv({ SIMHASH_SHADOW: "true" });
      const now = Math.floor(Date.now() / 1000);

      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBandItem("device-123", "1234567890abcdef", now)],
      });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );
      expect(result).toBeNull();
    });
  });

  describe("Input Validation", () => {
    it("returns null when fuzzy_hash is undefined", async () => {
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: undefined }),
      );
      expect(result).toBeNull();
    });

    it("returns null when fuzzy_hash is empty string", async () => {
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "" }),
      );
      expect(result).toBeNull();
    });

    it("returns null when fuzzy_hash is invalid hex", async () => {
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "not-a-valid-hash" }),
      );
      expect(result).toBeNull();
    });

    it("returns null when fuzzy_hash is too short", async () => {
      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234" }),
      );
      expect(result).toBeNull();
    });
  });

  describe("Band Queries", () => {
    it("queries all 4 bands in parallel", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      await tier15SimHashMatch(createDeps(), createFingerprint());

      const calls = dynamoMock.commandCalls(QueryCommand);
      expect(calls.length).toBe(4);
    });

    it("queries correct band partition keys", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      const calls = dynamoMock.commandCalls(QueryCommand);
      const pks = calls.map(
        (c) => c.args[0].input.ExpressionAttributeValues?.[":bk"]?.S,
      );
      expect(pks).toContain("SIMHASH_BAND#0#1234");
      expect(pks).toContain("SIMHASH_BAND#1#5678");
      expect(pks).toContain("SIMHASH_BAND#2#90ab");
      expect(pks).toContain("SIMHASH_BAND#3#cdef");
    });

    it("uses correct table name", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      const deps = createDeps();
      deps.tier2BucketsTable = "my-custom-table";
      await tier15SimHashMatch(deps, createFingerprint());

      const calls = dynamoMock.commandCalls(QueryCommand);
      expect(calls[0].args[0].input.TableName).toBe("my-custom-table");
    });

    it("applies per-band LIMIT", async () => {
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      await tier15SimHashMatch(createDeps(), createFingerprint());

      const calls = dynamoMock.commandCalls(QueryCommand);
      expect(calls[0].args[0].input.Limit).toBe(100);
    });
  });

  describe("Candidate Aggregation", () => {
    it("returns null when no candidates appear in 2+ bands", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("device-1", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("returns match when candidate appears in 2+ bands", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("device-match", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-match", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-match");
      expect(result!.match_tier).toBe(1.5);
      expect(result!.is_new_device).toBe(false);
      expect(result!.evidence_codes).toContain("SIMHASH_MATCH");
    });

    it("selects best candidate when multiple appear in 2+ bands", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [
            buildBandItem("device-closer", "1234567890abcde0", now),
            buildBandItem("device-farther", "1234567800000000", now),
          ],
        })
        .resolvesOnce({
          Items: [
            buildBandItem("device-closer", "1234567890abcde0", now),
            buildBandItem("device-farther", "1234567800000000", now),
          ],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-closer");
    });
  });

  describe("Hamming Distance Scoring", () => {
    it("accepts distance 0 (exact match)", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("device-exact", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-exact", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.simhash_details?.hamming_distance).toBe(0);
    });

    it("rejects candidates beyond threshold", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("device-far", "1234567890abffff", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-far", "1234567890abffff", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-far", "1234567890abffff", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890ab0000" }),
      );

      expect(result).toBeNull();
    });

    it("accepts candidates within threshold (distance 1-4)", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("device-close", "1234567890abcdee", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-close", "1234567890abcdee", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("device-close", "1234567890abcdee", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.simhash_details?.hamming_distance).toBeLessThanOrEqual(4);
    });
  });

  describe("Confidence Calculation", () => {
    it("distance 0 gives ~0.90 confidence", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it("more band matches give a bonus", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBandItem("dev", "1234567890abcdef", now)],
      });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.confidence).toBeGreaterThan(0.9);
    });

    it("confidence is capped at 0.95", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock.on(QueryCommand).resolves({
        Items: [buildBandItem("dev", "1234567890abcdef", now)],
      });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.confidence).toBeLessThanOrEqual(0.95);
    });

    it("confidence never drops below 0.6", async () => {
      const now = Math.floor(Date.now() / 1000);
      setSimHashEnv({ SIMHASH_HAMMING_THRESHOLD: "10" });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890ab0d0f", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890ab0d0f", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890ab0d0f", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      if (result) {
        expect(result.confidence).toBeGreaterThanOrEqual(0.6);
      }
    });
  });

  describe("Recency Gate", () => {
    it("accepts old device with distance 0 or 1", async () => {
      const oldTs = Math.floor(Date.now() / 1000) - 60 * 86400;

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("old-device", "1234567890abcdef", oldTs)],
        })
        .resolvesOnce({
          Items: [buildBandItem("old-device", "1234567890abcdef", oldTs)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
    });

    it("rejects old device with distance > 1", async () => {
      const oldTs = Math.floor(Date.now() / 1000) - 60 * 86400;
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("old-device", "1234567890abcdec", oldTs)],
        })
        .resolvesOnce({
          Items: [buildBandItem("old-device", "1234567890abcdec", oldTs)],
        })
        .resolvesOnce({
          Items: [buildBandItem("old-device", "1234567890abcdec", oldTs)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).toBeNull();
    });

    it("accepts recent device with distance > 1", async () => {
      const recentTs = Math.floor(Date.now() / 1000) - 5 * 86400;
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("recent-device", "1234567890abcdec", recentTs)],
        })
        .resolvesOnce({
          Items: [buildBandItem("recent-device", "1234567890abcdec", recentTs)],
        })
        .resolvesOnce({
          Items: [buildBandItem("recent-device", "1234567890abcdec", recentTs)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
    });
  });

  describe("Match Result Structure", () => {
    it("includes simhash_details", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.simhash_details).toBeDefined();
      expect(result!.simhash_details!.incoming_hash).toBe("1234567890abcdef");
      expect(result!.simhash_details!.matched_hash).toBe("1234567890abcdef");
      expect(result!.simhash_details!.hamming_distance).toBe(0);
      expect(result!.simhash_details!.similarity).toBe(1);
      expect(result!.simhash_details!.bands_matched).toBeGreaterThanOrEqual(2);
    });

    it("sets match_tier to 1.5", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result!.match_tier).toBe(1.5);
    });

    it("sets risk_score to 0.35", async () => {
      const now = Math.floor(Date.now() / 1000);
      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolvesOnce({
          Items: [buildBandItem("dev", "1234567890abcdef", now)],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result!.risk_score).toBe(0.35);
    });
  });

  describe("Error Handling", () => {
    it("fails open on DynamoDB error", async () => {
      dynamoMock.on(QueryCommand).rejects(new Error("DynamoDB unavailable"));

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });

    it("fails open on timeout", async () => {
      setSimHashEnv({ SIMHASH_LATENCY_BYPASS: "0" });
      dynamoMock.on(QueryCommand).resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint(),
      );
      expect(result).toBeNull();
    });
  });

  describe("Sorting and Tie-breaking", () => {
    it("prefers lower Hamming distance over recency", async () => {
      const now = Math.floor(Date.now() / 1000);
      const older = now - 1000;

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [
            buildBandItem("device-close", "1234567890abcdee", older),
            buildBandItem("device-far", "1234567890abcdec", now),
          ],
        })
        .resolvesOnce({
          Items: [
            buildBandItem("device-close", "1234567890abcdee", older),
            buildBandItem("device-far", "1234567890abcdec", now),
          ],
        })
        .resolvesOnce({
          Items: [
            buildBandItem("device-close", "1234567890abcdee", older),
            buildBandItem("device-far", "1234567890abcdec", now),
          ],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-close");
    });

    it("uses recency as tiebreaker at same distance", async () => {
      const now = Math.floor(Date.now() / 1000);
      const older = now - 1000;

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({
          Items: [
            buildBandItem("device-old", "1234567890abcdef", older),
            buildBandItem("device-new", "1234567890abcdef", now),
          ],
        })
        .resolvesOnce({
          Items: [
            buildBandItem("device-old", "1234567890abcdef", older),
            buildBandItem("device-new", "1234567890abcdef", now),
          ],
        })
        .resolves({ Items: [] });

      const result = await tier15SimHashMatch(
        createDeps(),
        createFingerprint({ fuzzy_hash: "1234567890abcdef" }),
      );

      expect(result).not.toBeNull();
      expect(result!.device_id).toBe("device-new");
    });
  });
});
