import { describe, it, expect, vi, beforeEach } from "vitest";
import { marshall } from "@aws-sdk/util-dynamodb";

const mockSend = vi.fn();

vi.mock("@aws-sdk/client-dynamodb", async () => {
  const actual = await vi.importActual<
    typeof import("@aws-sdk/client-dynamodb")
  >("@aws-sdk/client-dynamodb");
  return {
    ...actual,
    DynamoDBClient: class {
      send = (...args: unknown[]) => mockSend(...args);
    },
  };
});

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { CpiMerchantResolver } from "./cpi-merchant-resolver";

const ddb = new DynamoDBClient({});

beforeEach(() => {
  vi.clearAllMocks();
});

function makeResolver() {
  return new CpiMerchantResolver({ ddb, table: "merchant-keys-test" });
}

describe("CpiMerchantResolver", () => {
  it("queries cpi-index and returns the merchantId", async () => {
    mockSend.mockResolvedValueOnce({
      Items: [marshall({ keyId: "k1", merchantId: "m1", cpi: "c1" })],
    });
    const r = makeResolver();
    expect(await r.resolve("c1")).toBe("m1");
    const sent = mockSend.mock.calls[0][0];
    expect(sent.input).toMatchObject({
      TableName: "merchant-keys-test",
      IndexName: "cpi-index",
      KeyConditionExpression: "cpi = :cpi",
      Limit: 1,
    });
    expect(sent.input.ExpressionAttributeValues).toEqual({
      ":cpi": { S: "c1" },
    });
  });

  it("caches positive lookups for the resolver's lifetime", async () => {
    mockSend.mockResolvedValueOnce({
      Items: [marshall({ merchantId: "m1" })],
    });
    const r = makeResolver();
    expect(await r.resolve("c1")).toBe("m1");
    expect(await r.resolve("c1")).toBe("m1");
    expect(await r.resolve("c1")).toBe("m1");
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it("caches negative lookups with a TTL so unknown cpis don't trigger a Query per request", async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });
    const r = makeResolver();
    expect(await r.resolve("unknown")).toBeNull();
    expect(await r.resolve("unknown")).toBeNull();
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it("re-queries after the negative TTL elapses", async () => {
    vi.useFakeTimers();
    try {
      mockSend.mockResolvedValueOnce({ Items: [] });
      const r = makeResolver();
      expect(await r.resolve("unknown")).toBeNull();
      vi.advanceTimersByTime(60_001);
      mockSend.mockResolvedValueOnce({
        Items: [marshall({ merchantId: "m1" })],
      });
      expect(await r.resolve("unknown")).toBe("m1");
      expect(mockSend).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns null when the row has no merchantId attribute", async () => {
    mockSend.mockResolvedValueOnce({
      Items: [marshall({ keyId: "k1", cpi: "c1" })],
    });
    const r = makeResolver();
    expect(await r.resolve("c1")).toBeNull();
  });

  it("honors a custom index name", async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });
    const r = new CpiMerchantResolver({
      ddb,
      table: "merchant-keys-test",
      indexName: "alt-index",
    });
    await r.resolve("c1");
    expect(mockSend.mock.calls[0][0].input.IndexName).toBe("alt-index");
  });
});
