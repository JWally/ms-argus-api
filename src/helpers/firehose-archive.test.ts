import { describe, it, expect, vi, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import { archiveToFirehose } from "./firehose-archive";

const firehoseMock = mockClient(FirehoseClient);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

const baseDeps = {
  streamName: "test-stream",
  logger: mockLogger as any,
  metrics: mockMetrics as any,
  client: new FirehoseClient({}),
};

describe("archiveToFirehose", () => {
  beforeEach(() => {
    firehoseMock.reset();
    vi.clearAllMocks();
  });

  it("returns false and skips put when streamName is undefined", async () => {
    const ok = await archiveToFirehose(
      { foo: "bar" },
      { ...baseDeps, streamName: undefined },
    );
    expect(ok).toBe(false);
    expect(firehoseMock.commandCalls(PutRecordCommand)).toHaveLength(0);
  });

  it("sends record as newline-terminated NDJSON", async () => {
    firehoseMock.on(PutRecordCommand).resolves({ RecordId: "abc" });
    const item = { session_id: "s-1", x: 42 };

    const ok = await archiveToFirehose(item, baseDeps);

    expect(ok).toBe(true);
    const calls = firehoseMock.commandCalls(PutRecordCommand);
    expect(calls).toHaveLength(1);
    const input = calls[0].args[0].input;
    expect(input.DeliveryStreamName).toBe("test-stream");
    const body = Buffer.from(input.Record!.Data as Uint8Array).toString(
      "utf-8",
    );
    expect(body).toBe('{"session_id":"s-1","x":42}\n');
    expect(body.endsWith("\n")).toBe(true);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "FirehoseArchived",
      expect.anything(),
      1,
    );
  });

  it("swallows put errors and emits failure metric", async () => {
    firehoseMock.on(PutRecordCommand).rejects(new Error("throttled"));

    const ok = await archiveToFirehose({ a: 1 }, baseDeps);

    expect(ok).toBe(false);
    expect(mockLogger.warn).toHaveBeenCalledWith(
      "Firehose archive put failed",
      expect.objectContaining({ error: expect.any(Error) }),
    );
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "FirehoseArchiveFailed",
      expect.anything(),
      1,
    );
  });
});
