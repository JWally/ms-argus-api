import { describe, it, expect, vi, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { archivePayload } from "./archive";

const s3Mock = mockClient(S3Client);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

describe("archivePayload", () => {
  beforeEach(() => {
    s3Mock.reset();
    s3Mock.on(PutObjectCommand).resolves({});
    vi.clearAllMocks();
    vi.spyOn(Math, "random").mockReturnValue(0); // always sample
  });

  const baseDeps = {
    s3: new S3Client({}),
    bucket: "test-archive-bucket",
    sampleRate: 1.0,
    logger: mockLogger as any,
    metrics: mockMetrics as any,
  };

  it("should skip when s3 client is null", async () => {
    await archivePayload(
      "session-1",
      { foo: "bar" },
      { ...baseDeps, s3: null },
    );
    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
  });

  it("should skip when bucket is undefined", async () => {
    await archivePayload(
      "session-1",
      { foo: "bar" },
      {
        ...baseDeps,
        bucket: undefined,
      },
    );
    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
  });

  it("should skip when sampleRate is 0", async () => {
    await archivePayload(
      "session-1",
      { foo: "bar" },
      {
        ...baseDeps,
        sampleRate: 0,
      },
    );
    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
  });

  it("should skip when random exceeds sampleRate", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.9);
    await archivePayload(
      "session-1",
      { foo: "bar" },
      {
        ...baseDeps,
        sampleRate: 0.5,
      },
    );
    expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
  });

  it("should archive with gzip and low quality tag for thin payload", async () => {
    await archivePayload("session-1", { foo: "bar" }, baseDeps);

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input.ContentEncoding).toBe("gzip");
    expect(putCalls[0].args[0].input.Tagging).toBe("quality=low");
  });

  it("should tag as high quality when payload has structural hashes", async () => {
    const payload = {
      hashes: {
        maths: "hash1",
        windowFeatures: "hash2",
        htmlElementVersion: "hash3",
        css: "hash4",
      },
    };
    await archivePayload("session-1", payload, baseDeps);

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls[0].args[0].input.Tagging).toBe("quality=high");
  });

  it("should tag as low quality when fewer than 3 structural hashes", async () => {
    const payload = {
      hashes: { maths: "hash1", css: "hash2" },
    };
    await archivePayload("session-1", payload, baseDeps);

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    expect(putCalls[0].args[0].input.Tagging).toBe("quality=low");
  });

  it("should use Hive-partitioned key format", async () => {
    await archivePayload("session-123", { data: true }, baseDeps);

    const putCalls = s3Mock.commandCalls(PutObjectCommand);
    const key = putCalls[0].args[0].input.Key!;
    expect(key).toMatch(
      /^year=\d{4}\/month=\d{2}\/day=\d{2}\/hour=\d{2}\/session-123\.json\.gz$/,
    );
  });

  it("should handle S3 errors gracefully (not throw)", async () => {
    s3Mock.on(PutObjectCommand).rejects(new Error("S3 error"));
    await archivePayload("session-1", { data: true }, baseDeps);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "PayloadArchiveFailed",
      expect.any(String),
      1,
    );
  });

  it("should emit PayloadArchived metric on success", async () => {
    await archivePayload("session-1", { data: true }, baseDeps);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "PayloadArchived",
      expect.any(String),
      1,
    );
  });
});
