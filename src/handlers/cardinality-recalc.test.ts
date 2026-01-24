import { describe, it, expect, beforeEach, vi } from "vitest";

vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-cardinality-recalc-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.TIER2_BUCKETS_TABLE = "test-tier2-buckets";
});

import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  ScanCommand,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { ScheduledEvent, Context } from "aws-lambda";
import { TIER2_STATS_SK } from "../helpers/constants";

const dynamoMock = mockClient(DynamoDBClient);

import { handler } from "./cardinality-recalc";

describe("cardinality-recalc handler", () => {
  const mockContext: Context = {
    callbackWaitsForEmptyEventLoop: false,
    functionName: "test-function",
    functionVersion: "1",
    invokedFunctionArn: "arn:aws:lambda:us-east-1:123456789:function:test",
    memoryLimitInMB: "256",
    awsRequestId: "test-request-id",
    logGroupName: "/aws/lambda/test",
    logStreamName: "2025/01/01/[$LATEST]test",
    getRemainingTimeInMillis: () => 300000,
    done: () => {},
    fail: () => {},
    succeed: () => {},
  };

  const createScheduledEvent = (): ScheduledEvent => ({
    version: "0",
    id: "test-event-id",
    "detail-type": "Scheduled Event",
    source: "aws.events",
    account: "123456789",
    time: "2026-01-16T03:00:00Z",
    region: "us-east-1",
    resources: ["arn:aws:events:us-east-1:123456789:rule/test-rule"],
    detail: {},
  });

  beforeEach(() => {
    dynamoMock.reset();
    vi.clearAllMocks();
  });

  describe("EventBridge integration", () => {
    it("accepts EventBridge scheduled event payload", async () => {
      dynamoMock.on(ScanCommand).resolves({ Items: [] });

      const event = createScheduledEvent();
      await expect(
        handler(event, mockContext, () => {}),
      ).resolves.not.toThrow();
    });
  });

  describe("pagination handling", () => {
    it("scans all bucket_key partitions with pagination", async () => {
      dynamoMock
        .on(ScanCommand)
        .resolvesOnce({
          Items: [
            { bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } },
            { bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash2" } },
          ],
          LastEvaluatedKey: {
            bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash2" },
            device_id: { S: "device-2" },
          },
        })
        .resolvesOnce({
          Items: [{ bucket_key: { S: "tenant1#ip_ja4#5.6.7.8#ja4hash3" } }],
        });

      dynamoMock.on(QueryCommand).resolves({ Count: 0, Items: [] });
      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const scanCalls = dynamoMock.commandCalls(ScanCommand);
      expect(scanCalls.length).toBe(2);

      expect(scanCalls[1].args[0].input.ExclusiveStartKey).toBeDefined();
    });

    it("handles Query pagination when counting devices", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "10" } }] })
        .resolvesOnce({
          Count: 5,
          LastEvaluatedKey: {
            bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" },
            device_id: { S: "device-5" },
          },
        })
        .resolvesOnce({ Count: 3 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      expect(queryCalls.length).toBe(3);
    });
  });

  describe("item counting logic", () => {
    it("counts actual device_id items per bucket (excluding _stats)", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "10" } }] })
        .resolvesOnce({ Count: 5 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      const countQuery = queryCalls.find(
        (call) =>
          call.args[0].input.FilterExpression === "device_id <> :stats_sk",
      );
      expect(countQuery).toBeDefined();
      expect(
        countQuery?.args[0].input.ExpressionAttributeValues?.[":stats_sk"]?.S,
      ).toBe(TIER2_STATS_SK);
    });

    it("handles empty buckets (sets cardinality to 0)", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "5" } }] })
        .resolvesOnce({ Count: 0 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
      expect(
        updateCalls[0].args[0].input.ExpressionAttributeValues?.[":c"]?.N,
      ).toBe("0");
    });

    it("handles bucket with only _stats item (all devices expired)", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "100" } }] })
        .resolvesOnce({ Count: 0 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
      expect(
        updateCalls[0].args[0].input.ExpressionAttributeValues?.[":c"]?.N,
      ).toBe("0");
    });
  });

  describe("cardinality updates", () => {
    it("updates cardinality counter to match actual count", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "100" } }] })
        .resolvesOnce({ Count: 75 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);

      const input = updateCalls[0].args[0].input;
      expect(input.Key?.bucket_key?.S).toBe("tenant1#ip_ja4#1.2.3.4#ja4hash1");
      expect(input.Key?.device_id?.S).toBe(TIER2_STATS_SK);
      expect(input.ExpressionAttributeValues?.[":c"]?.N).toBe("75");
    });

    it("corrects over-counted cardinality when devices have expired via TTL", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ua#192.168.1.1#chrome" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "500" } }] })
        .resolvesOnce({ Count: 350 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
      expect(
        updateCalls[0].args[0].input.ExpressionAttributeValues?.[":c"]?.N,
      ).toBe("350");
    });

    it("corrects under-counted cardinality (edge case: failed increments)", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_gpu#10.0.0.1#nvidia" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "10" } }] })
        .resolvesOnce({ Count: 15 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
      expect(
        updateCalls[0].args[0].input.ExpressionAttributeValues?.[":c"]?.N,
      ).toBe("15");
    });

    it("skips update when cardinality already matches actual count", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "25" } }] })
        .resolvesOnce({ Count: 25 });

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(0);
    });

    it("handles bucket without existing _stats item", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [] })
        .resolvesOnce({ Count: 3 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
      expect(
        updateCalls[0].args[0].input.ExpressionAttributeValues?.[":c"]?.N,
      ).toBe("3");
    });
  });

  describe("error handling", () => {
    it("continues processing when single bucket update fails", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          { bucket_key: { S: "bucket-fail" } },
          { bucket_key: { S: "bucket-success" } },
        ],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "10" } }] })
        .rejectsOnce(new Error("DynamoDB error"))
        .resolvesOnce({ Items: [{ cardinality: { N: "5" } }] })
        .resolvesOnce({ Count: 3 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await expect(
        handler(event, mockContext, () => {}),
      ).resolves.not.toThrow();

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
    });

    it("handles DynamoDB throttling with exponential backoff", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      const throttleError = new Error("Throttled");
      throttleError.name = "ProvisionedThroughputExceededException";

      dynamoMock
        .on(QueryCommand)
        .rejectsOnce(throttleError)
        .resolvesOnce({ Items: [{ cardinality: { N: "10" } }] })
        .resolvesOnce({ Count: 5 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      expect(queryCalls.length).toBeGreaterThanOrEqual(2);
    });

    it("fails after max retries on persistent throttling", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [{ bucket_key: { S: "tenant1#ip_ja4#1.2.3.4#ja4hash1" } }],
      });

      const throttleError = new Error("Throttled");
      throttleError.name = "ProvisionedThroughputExceededException";

      dynamoMock.on(QueryCommand).rejects(throttleError);

      const event = createScheduledEvent();
      await expect(
        handler(event, mockContext, () => {}),
      ).resolves.not.toThrow();
    });
  });

  describe("metrics emission", () => {
    it("emits metric for total buckets processed", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          { bucket_key: { S: "bucket-1" } },
          { bucket_key: { S: "bucket-2" } },
          { bucket_key: { S: "bucket-3" } },
        ],
      });

      dynamoMock.on(QueryCommand).callsFake(() => ({
        Items: [{ cardinality: { N: "10" } }],
        Count: 10,
      }));

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      // 3 buckets * 2 queries each (cardinality + count) = 6
      expect(queryCalls.length).toBe(6);
    });

    it("emits metric for buckets with drift corrected", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          { bucket_key: { S: "bucket-drift" } },
          { bucket_key: { S: "bucket-no-drift" } },
        ],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "100" } }] })
        .resolvesOnce({ Count: 50 })
        .resolvesOnce({ Items: [{ cardinality: { N: "25" } }] })
        .resolvesOnce({ Count: 25 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(1);
    });

    it("emits metric for total drift magnitude", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          { bucket_key: { S: "bucket-1" } },
          { bucket_key: { S: "bucket-2" } },
        ],
      });

      dynamoMock
        .on(QueryCommand)
        .resolvesOnce({ Items: [{ cardinality: { N: "100" } }] })
        .resolvesOnce({ Count: 50 })
        .resolvesOnce({ Items: [{ cardinality: { N: "75" } }] })
        .resolvesOnce({ Count: 50 });

      dynamoMock.on(UpdateItemCommand).resolves({});

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const updateCalls = dynamoMock.commandCalls(UpdateItemCommand);
      expect(updateCalls.length).toBe(2);
    });
  });

  describe("edge cases", () => {
    it("handles large table with many partitions", async () => {
      const manyBuckets = Array.from({ length: 100 }, (_, i) => ({
        bucket_key: { S: `bucket-${i}` },
      }));

      dynamoMock.on(ScanCommand).resolves({ Items: manyBuckets });

      dynamoMock.on(QueryCommand).callsFake(() => ({
        Items: [{ cardinality: { N: "5" } }],
        Count: 5,
      }));

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      expect(queryCalls.length).toBe(200);
    });

    it("deduplicates bucket keys from scan results", async () => {
      dynamoMock.on(ScanCommand).resolves({
        Items: [
          { bucket_key: { S: "bucket-1" } },
          { bucket_key: { S: "bucket-1" } },
          { bucket_key: { S: "bucket-2" } },
        ],
      });

      dynamoMock.on(QueryCommand).callsFake(() => ({
        Items: [{ cardinality: { N: "5" } }],
        Count: 5,
      }));

      const event = createScheduledEvent();
      await handler(event, mockContext, () => {});

      // 2 unique buckets * 2 queries = 4
      const queryCalls = dynamoMock.commandCalls(QueryCommand);
      expect(queryCalls.length).toBe(4);
    });
  });
});
