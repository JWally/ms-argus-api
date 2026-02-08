import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import {
  buildIdentityIndexEntries,
  batchWriteTier1Indexes,
  writeAnchorBucket,
  ASSOCIATION_ALLOWED_EVIDENCE,
  type IndexWriterDeps,
  type Tier1IndexEntry,
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

  describe("fuzzy_hash in identity index entries for drift detection", () => {
    it("should include fuzzy_hash in buildIdentityIndexEntries", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        public_key: "pubkey123",
        fuzzy_hash: "fedcba9876543210",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      for (const entry of entries) {
        expect(entry.fuzzy_hash).toBe("fedcba9876543210");
      }
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
