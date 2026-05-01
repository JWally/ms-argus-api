import { describe, it, expect, vi, beforeEach } from "vitest";

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
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { decrementCredit } from "./credits";

const ddb = new DynamoDBClient({});
const deps = { ddb, table: "merchants-test" };

beforeEach(() => {
  vi.clearAllMocks();
});

describe("decrementCredit", () => {
  it("returns ok with new remaining when the conditional update succeeds", async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { credits: { N: "199" } } });
    const result = await decrementCredit("m1", deps);
    expect(result).toEqual({ ok: true, remaining: 199 });
    const sent = mockSend.mock.calls[0][0];
    expect(sent.input).toMatchObject({
      TableName: "merchants-test",
      Key: { merchantId: { S: "m1" } },
      UpdateExpression: "SET credits = credits - :one",
      ConditionExpression: "credits >= :one AND active = :t",
      ReturnValues: "UPDATED_NEW",
    });
    expect(sent.input.ExpressionAttributeValues).toEqual({
      ":one": { N: "1" },
      ":t": { BOOL: true },
    });
  });

  it("returns insufficient_credits when the conditional check fails", async () => {
    const err = new ConditionalCheckFailedException({
      $metadata: {},
      message: "conditional check failed",
    });
    mockSend.mockRejectedValueOnce(err);
    const result = await decrementCredit("m1", deps);
    expect(result).toEqual({ ok: false, reason: "insufficient_credits" });
  });

  it("rethrows non-conditional errors so the handler 5xxs cleanly", async () => {
    mockSend.mockRejectedValueOnce(new Error("throttled"));
    await expect(decrementCredit("m1", deps)).rejects.toThrow(/throttled/);
  });

  it("falls back to remaining=0 when DDB returns no Attributes", async () => {
    mockSend.mockResolvedValueOnce({});
    const result = await decrementCredit("m1", deps);
    expect(result).toEqual({ ok: true, remaining: 0 });
  });
});
