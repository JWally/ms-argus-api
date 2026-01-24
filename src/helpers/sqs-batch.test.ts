import { describe, it, expect, vi } from "vitest";
import { SQSRecord } from "aws-lambda";
import { processSqsBatch, SqsBatchOptions } from "./sqs-batch";

function createMockRecord(messageId: string, body: string): SQSRecord {
  return {
    messageId,
    body,
    receiptHandle: "receipt",
    attributes: {
      ApproximateReceiveCount: "1",
      SentTimestamp: "0",
      SenderId: "sender",
      ApproximateFirstReceiveTimestamp: "0",
    },
    messageAttributes: {},
    md5OfBody: "md5",
    eventSource: "aws:sqs",
    eventSourceARN: "arn:aws:sqs:us-east-1:123456789:queue",
    awsRegion: "us-east-1",
  };
}

function createOpts(overrides?: Partial<SqsBatchOptions>): SqsBatchOptions {
  return {
    metrics: {
      addMetric: vi.fn(),
      publishStoredMetrics: vi.fn(),
    } as unknown as SqsBatchOptions["metrics"],
    logger: {
      error: vi.fn(),
    } as unknown as SqsBatchOptions["logger"],
    successMetric: "TestSuccess",
    errorMetric: "TestError",
    ...overrides,
  };
}

describe("processSqsBatch", () => {
  it("returns empty batchItemFailures when all records succeed", async () => {
    const records = [createMockRecord("1", "a"), createMockRecord("2", "b")];
    const processRecord = vi.fn().mockResolvedValue(undefined);
    const opts = createOpts();

    const result = await processSqsBatch(records, processRecord, opts);

    expect(result.batchItemFailures).toEqual([]);
    expect(processRecord).toHaveBeenCalledTimes(2);
    expect(opts.metrics.addMetric).toHaveBeenCalledWith(
      "TestSuccess",
      expect.anything(),
      1,
    );
    expect(opts.metrics.publishStoredMetrics).toHaveBeenCalledOnce();
  });

  it("reports failed records in batchItemFailures", async () => {
    const records = [createMockRecord("1", "a"), createMockRecord("2", "b")];
    const processRecord = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("fail"));
    const opts = createOpts();

    const result = await processSqsBatch(records, processRecord, opts);

    expect(result.batchItemFailures).toEqual([{ itemIdentifier: "2" }]);
    expect(opts.metrics.addMetric).toHaveBeenCalledWith(
      "TestSuccess",
      expect.anything(),
      1,
    );
    expect(opts.metrics.addMetric).toHaveBeenCalledWith(
      "TestError",
      expect.anything(),
      1,
    );
    expect(opts.logger.error).toHaveBeenCalledWith(
      "Failed to process record",
      expect.objectContaining({ messageId: "2" }),
    );
  });

  it("handles empty records array", async () => {
    const processRecord = vi.fn();
    const opts = createOpts();

    const result = await processSqsBatch([], processRecord, opts);

    expect(result.batchItemFailures).toEqual([]);
    expect(processRecord).not.toHaveBeenCalled();
    expect(opts.metrics.publishStoredMetrics).toHaveBeenCalledOnce();
  });

  it("continues processing after a failure", async () => {
    const records = [
      createMockRecord("1", "a"),
      createMockRecord("2", "b"),
      createMockRecord("3", "c"),
    ];
    const processRecord = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("fail"))
      .mockResolvedValueOnce(undefined);
    const opts = createOpts();

    const result = await processSqsBatch(records, processRecord, opts);

    expect(result.batchItemFailures).toEqual([{ itemIdentifier: "2" }]);
    expect(processRecord).toHaveBeenCalledTimes(3);
  });

  it("reports all failures when all records fail", async () => {
    const records = [createMockRecord("1", "a"), createMockRecord("2", "b")];
    const processRecord = vi.fn().mockRejectedValue(new Error("fail"));
    const opts = createOpts();

    const result = await processSqsBatch(records, processRecord, opts);

    expect(result.batchItemFailures).toHaveLength(2);
    expect(result.batchItemFailures).toEqual([
      { itemIdentifier: "1" },
      { itemIdentifier: "2" },
    ]);
  });
});
