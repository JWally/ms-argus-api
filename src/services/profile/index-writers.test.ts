import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  buildTier1IndexEntries,
  buildIdentityIndexEntries,
  buildHashIndexEntries,
  batchWriteTier1Indexes,
  batchWriteTier2Buckets,
  incrementBucketCardinalities,
  writeAnchorBucket,
  buildSimHashBandEntries,
  batchWriteSimHashBands,
  ASSOCIATION_ALLOWED_EVIDENCE,
  type IndexWriterDeps,
  type Tier1IndexEntry,
  type Tier2BucketEntry,
  type SimHashBandEntry,
} from "./index-writers";
import { Fingerprint } from "./types";

const dynamoMock = mockClient(DynamoDBClient);

describe("Tier-gated identity association", () => {
  const ttl = 1705000000;

  describe("ASSOCIATION_ALLOWED_EVIDENCE", () => {
    it("should contain Tier 0.5 identity codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("PUBLIC_KEY_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("EVERCOOKIE_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("SIGINT_ID_MATCH");
    });

    it("should contain Tier 1 hash codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("STABLE_HASH_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("FUZZY_HASH_MATCH");
    });

    it("should contain time-bounded anchor codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("SESSION_ANCHOR_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("IP_UA_ANCHOR_BUCKET");
    });

    it("should NOT contain unbounded Tier 2 bucket codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("IP_JA4_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain(
        "GPU_SCREEN_TZ_BUCKET",
      );
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("AUDIO_CANVAS_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("MATHS_WINDOW_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("HTML_CSS_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("WEBGL_STRUCT_BUCKET");
    });

    it("should contain NEW_DEVICE code", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("NEW_DEVICE");
    });
  });

  describe("buildIdentityIndexEntries", () => {
    it("should return empty array when no identity fields present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);
      expect(entries).toEqual([]);
    });

    it("should build pubkey# entry for public_key", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = { public_key: publicKey };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: `pubkey#${publicKey}`,
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build evercookie# entry for evercookie_id", () => {
      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "evercookie#cookie123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build sigint# entry for sigint_id", () => {
      const fingerprint: Fingerprint = { sigint_id: "sigint-uuid-123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "sigint#sigint-uuid-123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build all identity entries when all identity fields present", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(3);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain(`pubkey#${publicKey}`);
      expect(hashKeys).toContain("evercookie#cookie123");
      expect(hashKeys).toContain("sigint#sigint-uuid-123");
      expect(hashKeys).not.toContain("stable#stable123");
      expect(hashKeys).not.toContain("fuzzy#fuzzy456");
    });
  });

  describe("buildHashIndexEntries", () => {
    it("should return empty array when no hash fields present", () => {
      const fingerprint: Fingerprint = {
        public_key: "MFkwE...",
        evercookie_id: "cookie123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);
      expect(entries).toEqual([]);
    });

    it("should build stable# entry for stable_hash", () => {
      const fingerprint: Fingerprint = { stable_hash: "stable123" };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "stable#stable123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build fuzzy# entry for fuzzy_hash", () => {
      const fingerprint: Fingerprint = { fuzzy_hash: "fuzzy456" };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "fuzzy#fuzzy456",
        device_id: "dev_123",
        fuzzy_hash: "fuzzy456",
        ttl,
      });
    });

    it("should build all hash entries when all hash fields present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
        public_key: "MFkwE...",
        evercookie_id: "cookie123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain("stable#stable123");
      expect(hashKeys).toContain("fuzzy#fuzzy456");
      expect(hashKeys).not.toContain("pubkey#MFkwE...");
      expect(hashKeys).not.toContain("evercookie#cookie123");
    });
  });

  describe("buildTier1IndexEntries (backward compatibility)", () => {
    it("should still return all entries for full fingerprint", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildTier1IndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(5);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain(`pubkey#${publicKey}`);
      expect(hashKeys).toContain("evercookie#cookie123");
      expect(hashKeys).toContain("sigint#sigint-uuid-123");
      expect(hashKeys).toContain("stable#stable123");
      expect(hashKeys).toContain("fuzzy#fuzzy456");
    });
  });

  describe("fuzzy_hash in index entries for drift detection", () => {
    it("should include fuzzy_hash in buildTier1IndexEntries", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable123",
        fuzzy_hash: "0123456789abcdef",
      };
      const entries = buildTier1IndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(3);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("0123456789abcdef");
      });
    });

    it("should include fuzzy_hash in buildIdentityIndexEntries", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        public_key: "pubkey123",
        fuzzy_hash: "fedcba9876543210",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("fedcba9876543210");
      });
    });

    it("should include fuzzy_hash in buildHashIndexEntries", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "abcd1234efgh5678",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("abcd1234efgh5678");
      });
    });

    it("should include undefined fuzzy_hash when not present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0].fuzzy_hash).toBeUndefined();
    });
  });
});

function createDeps(): IndexWriterDeps {
  return {
    dynamodb: new DynamoDBClient({}),
    tier1IndexTable: "test-tier1-index",
    tier2BucketsTable: "test-tier2-buckets",
  };
}

describe("batchWriteTier1Indexes", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  it("writes entries to DynamoDB with correct table name", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: Tier1IndexEntry[] = [
      { hash_key: "stable#abc", device_id: "dev-1", ttl: 1700000000 },
      {
        hash_key: "fuzzy#def",
        device_id: "dev-1",
        fuzzy_hash: "def",
        ttl: 1700000000,
      },
    ];

    await batchWriteTier1Indexes(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(1);
    expect(
      calls[0].args[0].input.RequestItems!["test-tier1-index"],
    ).toHaveLength(2);
  });

  it("handles empty entries array", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    await batchWriteTier1Indexes(createDeps(), []);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(0);
  });

  it("retries unprocessed items with backoff", async () => {
    const entries: Tier1IndexEntry[] = [
      { hash_key: "stable#abc", device_id: "dev-1", ttl: 1700000000 },
    ];

    dynamoMock
      .on(BatchWriteItemCommand)
      .resolvesOnce({
        UnprocessedItems: {
          "test-tier1-index": [
            { PutRequest: { Item: { hash_key: { S: "stable#abc" } } } },
          ],
        },
      })
      .resolvesOnce({ UnprocessedItems: {} });

    await batchWriteTier1Indexes(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(2);
  });

  it("throws after max retries exceeded", async () => {
    const entries: Tier1IndexEntry[] = [
      { hash_key: "stable#abc", device_id: "dev-1", ttl: 1700000000 },
    ];

    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: {
        "test-tier1-index": [
          { PutRequest: { Item: { hash_key: { S: "stable#abc" } } } },
        ],
      },
    });

    await expect(
      batchWriteTier1Indexes(createDeps(), entries, 2),
    ).rejects.toThrow("Failed to write 1 Tier1 index items after 2 retries");
  });

  it("removes undefined values from marshalled entries", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: Tier1IndexEntry[] = [
      {
        hash_key: "stable#abc",
        device_id: "dev-1",
        fuzzy_hash: undefined,
        ttl: 1700000000,
      },
    ];

    await batchWriteTier1Indexes(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    const item =
      calls[0].args[0].input.RequestItems!["test-tier1-index"]![0].PutRequest!
        .Item!;
    expect(item.fuzzy_hash).toBeUndefined();
  });
});

describe("batchWriteTier2Buckets", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  it("writes bucket entries with correct attributes", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: Tier2BucketEntry[] = [
      {
        bucket_key: "ip_ja4#1.2.3.4#ja4hash",
        device_id: "dev-1",
        ttl: 1700000000,
      },
    ];

    await batchWriteTier2Buckets(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(1);
    const item =
      calls[0].args[0].input.RequestItems!["test-tier2-buckets"]![0].PutRequest!
        .Item!;
    expect(item.bucket_key.S).toBe("ip_ja4#1.2.3.4#ja4hash");
    expect(item.device_id.S).toBe("dev-1");
    expect(item.ttl.N).toBe("1700000000");
  });

  it("retries unprocessed items", async () => {
    const entries: Tier2BucketEntry[] = [
      { bucket_key: "ip_ja4#key", device_id: "dev-1", ttl: 1700000000 },
    ];

    dynamoMock
      .on(BatchWriteItemCommand)
      .resolvesOnce({
        UnprocessedItems: {
          "test-tier2-buckets": [
            { PutRequest: { Item: { bucket_key: { S: "ip_ja4#key" } } } },
          ],
        },
      })
      .resolvesOnce({ UnprocessedItems: {} });

    await batchWriteTier2Buckets(createDeps(), entries);

    expect(dynamoMock.commandCalls(BatchWriteItemCommand)).toHaveLength(2);
  });

  it("throws after max retries exceeded", async () => {
    const entries: Tier2BucketEntry[] = [
      { bucket_key: "ip_ja4#key", device_id: "dev-1", ttl: 1700000000 },
    ];

    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: {
        "test-tier2-buckets": [
          { PutRequest: { Item: { bucket_key: { S: "ip_ja4#key" } } } },
        ],
      },
    });

    await expect(
      batchWriteTier2Buckets(createDeps(), entries, 2),
    ).rejects.toThrow("Failed to write 1 Tier2 bucket items after 2 retries");
  });

  it("succeeds on first attempt when no unprocessed items", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: Tier2BucketEntry[] = [
      { bucket_key: "key1", device_id: "dev-1", ttl: 1700000000 },
      { bucket_key: "key2", device_id: "dev-2", ttl: 1700000000 },
    ];

    await batchWriteTier2Buckets(createDeps(), entries);

    expect(dynamoMock.commandCalls(BatchWriteItemCommand)).toHaveLength(1);
  });
});

describe("incrementBucketCardinalities", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  it("sends UpdateItem for each bucket key", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    const bucketKeys = [
      "ip_ja4#1.2.3.4#ja4",
      "gpu_screen_tz#nvidia#1920x1080#EST",
    ];
    await incrementBucketCardinalities(createDeps(), bucketKeys, 1700000000);

    const calls = dynamoMock.commandCalls(UpdateItemCommand);
    expect(calls).toHaveLength(2);
  });

  it("uses _stats as sort key", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    await incrementBucketCardinalities(
      createDeps(),
      ["ip_ja4#key"],
      1700000000,
    );

    const call = dynamoMock.commandCalls(UpdateItemCommand)[0];
    expect(call.args[0].input.Key!.device_id.S).toBe("_stats");
  });

  it("uses ADD expression for atomic increment", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    await incrementBucketCardinalities(
      createDeps(),
      ["ip_ja4#key"],
      1700000000,
    );

    const call = dynamoMock.commandCalls(UpdateItemCommand)[0];
    expect(call.args[0].input.UpdateExpression).toContain(
      "ADD cardinality :inc",
    );
    expect(call.args[0].input.ExpressionAttributeValues![":inc"].N).toBe("1");
  });

  it("sets TTL on stats entry", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    await incrementBucketCardinalities(createDeps(), ["key1"], 1700000000);

    const call = dynamoMock.commandCalls(UpdateItemCommand)[0];
    expect(call.args[0].input.ExpressionAttributeValues![":ttl"].N).toBe(
      "1700000000",
    );
  });

  it("handles empty bucket keys array", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    await incrementBucketCardinalities(createDeps(), [], 1700000000);

    expect(dynamoMock.commandCalls(UpdateItemCommand)).toHaveLength(0);
  });

  it("executes all updates in parallel", async () => {
    dynamoMock.on(UpdateItemCommand).resolves({});

    const keys = ["key1", "key2", "key3"];
    await incrementBucketCardinalities(createDeps(), keys, 1700000000);

    expect(dynamoMock.commandCalls(UpdateItemCommand)).toHaveLength(3);
  });
});

describe("writeAnchorBucket", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  it("writes PutItem with correct table and keys (session anchor)", async () => {
    dynamoMock.on(PutItemCommand).resolves({});

    await writeAnchorBucket(
      createDeps(),
      "session_anchor#1.2.3.4#hash#1920x1080",
      "dev-1",
    );

    const calls = dynamoMock.commandCalls(PutItemCommand);
    expect(calls).toHaveLength(1);
    const input = calls[0].args[0].input;
    expect(input.TableName).toBe("test-tier2-buckets");
    expect(input.Item!.bucket_key.S).toBe(
      "session_anchor#1.2.3.4#hash#1920x1080",
    );
    expect(input.Item!.device_id.S).toBe("dev-1");
  });

  it("writes PutItem with correct table and keys (ip_ua anchor)", async () => {
    dynamoMock.on(PutItemCommand).resolves({});

    await writeAnchorBucket(createDeps(), "ip_ua_anchor#1.2.3.4#hash", "dev-2");

    const calls = dynamoMock.commandCalls(PutItemCommand);
    expect(calls).toHaveLength(1);
    const input = calls[0].args[0].input;
    expect(input.TableName).toBe("test-tier2-buckets");
    expect(input.Item!.bucket_key.S).toBe("ip_ua_anchor#1.2.3.4#hash");
    expect(input.Item!.device_id.S).toBe("dev-2");
  });

  it("includes created_at timestamp", async () => {
    dynamoMock.on(PutItemCommand).resolves({});
    const before = Date.now();

    await writeAnchorBucket(createDeps(), "key", "dev-1");

    const after = Date.now();
    const calls = dynamoMock.commandCalls(PutItemCommand);
    const createdAt = Number(calls[0].args[0].input.Item!.created_at.N);
    expect(createdAt).toBeGreaterThanOrEqual(before);
    expect(createdAt).toBeLessThanOrEqual(after);
  });

  it("sets TTL ~1 hour from now", async () => {
    dynamoMock.on(PutItemCommand).resolves({});

    await writeAnchorBucket(createDeps(), "key", "dev-1");

    const calls = dynamoMock.commandCalls(PutItemCommand);
    const ttl = Number(calls[0].args[0].input.Item!.ttl.N);
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(ttl - nowSeconds).toBeGreaterThan(3500);
    expect(ttl - nowSeconds).toBeLessThanOrEqual(3600);
  });
});

describe("buildSimHashBandEntries", () => {
  it("returns 4 band entries for valid 16-char hex fuzzy_hash", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint, 1700000000);

    expect(entries).toHaveLength(4);
  });

  it("returns empty array when fuzzy_hash is missing", () => {
    const fingerprint: Fingerprint = { stable_hash: "abc" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint);

    expect(entries).toEqual([]);
  });

  it("returns empty array for invalid fuzzy_hash (wrong length)", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "abc" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint);

    expect(entries).toEqual([]);
  });

  it("sets correct bucket_key format for each band", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint, 1700000000);

    entries.forEach((entry) => {
      expect(entry.bucket_key).toMatch(/^SIMHASH_BAND#\d#[0-9a-f]{4}$/);
    });
  });

  it("sets device_id as inverted timestamp SK", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint, 1700000000);

    entries.forEach((entry) => {
      expect(entry.device_id).toMatch(/^t#\d{13}#dev-1$/);
    });
  });

  it("includes fuzzy_hash in each entry", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint, 1700000000);

    entries.forEach((entry) => {
      expect(entry.fuzzy_hash).toBe("0123456789abcdef");
    });
  });

  it("sets last_seen to provided timestamp", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const entries = buildSimHashBandEntries("dev-1", fingerprint, 1700000000);

    entries.forEach((entry) => {
      expect(entry.last_seen).toBe(1700000000);
    });
  });

  it("sets TTL based on BAND_TTL_DAYS from timestamp", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const timestamp = 1700000000;
    const entries = buildSimHashBandEntries("dev-1", fingerprint, timestamp);

    const expectedTtl = timestamp + 90 * 86400;
    entries.forEach((entry) => {
      expect(entry.ttl).toBe(expectedTtl);
    });
  });

  it("uses current time when timestamp not provided", () => {
    const fingerprint: Fingerprint = { fuzzy_hash: "0123456789abcdef" };
    const before = Math.floor(Date.now() / 1000);
    const entries = buildSimHashBandEntries("dev-1", fingerprint);
    const after = Math.floor(Date.now() / 1000);

    entries.forEach((entry) => {
      expect(entry.last_seen).toBeGreaterThanOrEqual(before);
      expect(entry.last_seen).toBeLessThanOrEqual(after);
    });
  });
});

describe("batchWriteSimHashBands", () => {
  beforeEach(() => {
    dynamoMock.reset();
  });

  it("returns immediately for empty entries", async () => {
    await batchWriteSimHashBands(createDeps(), []);
    expect(dynamoMock.commandCalls(BatchWriteItemCommand)).toHaveLength(0);
  });

  it("writes band entries with correct attributes", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: SimHashBandEntry[] = [
      {
        bucket_key: "SIMHASH_BAND#0#0123",
        device_id: "t#8299999999999#dev-1",
        fuzzy_hash: "0123456789abcdef",
        last_seen: 1700000000,
        ttl: 1707776000,
      },
    ];

    await batchWriteSimHashBands(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(1);
    const item =
      calls[0].args[0].input.RequestItems!["test-tier2-buckets"]![0].PutRequest!
        .Item!;
    expect(item.bucket_key.S).toBe("SIMHASH_BAND#0#0123");
    expect(item.device_id.S).toBe("t#8299999999999#dev-1");
    expect(item.fuzzy_hash.S).toBe("0123456789abcdef");
    expect(item.last_seen.N).toBe("1700000000");
    expect(item.ttl.N).toBe("1707776000");
  });

  it("retries unprocessed items", async () => {
    const entries: SimHashBandEntry[] = [
      {
        bucket_key: "SIMHASH_BAND#0#0123",
        device_id: "t#inv#dev-1",
        fuzzy_hash: "0123456789abcdef",
        last_seen: 1700000000,
        ttl: 1707776000,
      },
    ];

    dynamoMock
      .on(BatchWriteItemCommand)
      .resolvesOnce({
        UnprocessedItems: {
          "test-tier2-buckets": [
            {
              PutRequest: {
                Item: { bucket_key: { S: "SIMHASH_BAND#0#0123" } },
              },
            },
          ],
        },
      })
      .resolvesOnce({ UnprocessedItems: {} });

    await batchWriteSimHashBands(createDeps(), entries);

    expect(dynamoMock.commandCalls(BatchWriteItemCommand)).toHaveLength(2);
  });

  it("throws after max retries exceeded", async () => {
    const entries: SimHashBandEntry[] = [
      {
        bucket_key: "SIMHASH_BAND#0#0123",
        device_id: "t#inv#dev-1",
        fuzzy_hash: "0123456789abcdef",
        last_seen: 1700000000,
        ttl: 1707776000,
      },
    ];

    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: {
        "test-tier2-buckets": [
          {
            PutRequest: { Item: { bucket_key: { S: "SIMHASH_BAND#0#0123" } } },
          },
        ],
      },
    });

    await expect(
      batchWriteSimHashBands(createDeps(), entries, 2),
    ).rejects.toThrow("Failed to write 1 SimHash band items after 2 retries");
  });

  it("writes multiple band entries in single batch", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({ UnprocessedItems: {} });

    const entries: SimHashBandEntry[] = [
      {
        bucket_key: "SIMHASH_BAND#0#0123",
        device_id: "sk1",
        fuzzy_hash: "h1",
        last_seen: 1,
        ttl: 2,
      },
      {
        bucket_key: "SIMHASH_BAND#1#4567",
        device_id: "sk2",
        fuzzy_hash: "h2",
        last_seen: 1,
        ttl: 2,
      },
      {
        bucket_key: "SIMHASH_BAND#2#89ab",
        device_id: "sk3",
        fuzzy_hash: "h3",
        last_seen: 1,
        ttl: 2,
      },
      {
        bucket_key: "SIMHASH_BAND#3#cdef",
        device_id: "sk4",
        fuzzy_hash: "h4",
        last_seen: 1,
        ttl: 2,
      },
    ];

    await batchWriteSimHashBands(createDeps(), entries);

    const calls = dynamoMock.commandCalls(BatchWriteItemCommand);
    expect(calls).toHaveLength(1);
    expect(
      calls[0].args[0].input.RequestItems!["test-tier2-buckets"],
    ).toHaveLength(4);
  });
});
