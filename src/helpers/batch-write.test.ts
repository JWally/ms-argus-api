import { describe, it, expect, beforeEach } from "vitest";
import { DynamoDBClient, WriteRequest } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { BatchWriteItemCommand } from "@aws-sdk/client-dynamodb";
import { batchWriteWithRetry } from "./batch-write";

const dynamoMock = mockClient(DynamoDBClient);

beforeEach(() => {
  dynamoMock.reset();
});

describe("batchWriteWithRetry", () => {
  const tableName = "test-table";
  const entityName = "Test";

  const makeItems = (count: number): WriteRequest[] =>
    Array.from({ length: count }, (_, i) => ({
      PutRequest: {
        Item: { pk: { S: `item-${i}` } },
      },
    }));

  it("writes items successfully in a single attempt", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({});
    const items = makeItems(3);

    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items,
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(1);
  });

  it("returns immediately for empty items array", async () => {
    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items: [],
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(0);
  });

  it("retries unprocessed items", async () => {
    const items = makeItems(3);

    dynamoMock
      .on(BatchWriteItemCommand)
      .resolvesOnce({
        UnprocessedItems: { [tableName]: [items[2]] },
      })
      .resolvesOnce({});

    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items,
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(2);
  });

  it("throws after max retries exceeded", async () => {
    const items = makeItems(2);

    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: { [tableName]: [items[0]] },
    });

    await expect(
      batchWriteWithRetry(new DynamoDBClient({}), {
        tableName,
        items,
        entityName,
        maxRetries: 2,
      }),
    ).rejects.toThrow("Failed to write 1 Test items after 2 retries");
  });

  it("stops retrying when all items are processed", async () => {
    const items = makeItems(5);

    dynamoMock
      .on(BatchWriteItemCommand)
      .resolvesOnce({
        UnprocessedItems: { [tableName]: items.slice(3) },
      })
      .resolvesOnce({
        UnprocessedItems: { [tableName]: [items[4]] },
      })
      .resolvesOnce({});

    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items,
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(3);
  });

  it("handles undefined UnprocessedItems as success", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: undefined,
    });

    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items: makeItems(2),
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(1);
  });

  it("handles empty UnprocessedItems array as success", async () => {
    dynamoMock.on(BatchWriteItemCommand).resolves({
      UnprocessedItems: { [tableName]: [] },
    });

    await batchWriteWithRetry(new DynamoDBClient({}), {
      tableName,
      items: makeItems(2),
      entityName,
    });

    expect(dynamoMock.calls()).toHaveLength(1);
  });
});
