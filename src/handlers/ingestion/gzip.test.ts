import { describe, it, expect, vi, beforeEach } from "vitest";
import { decompressPayload } from "./gzip";
import { HttpError } from "../../helpers/http-error";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { gzipSync } from "zlib";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

function createMockMetrics(): Metrics {
  return {
    addMetric: vi.fn(),
  } as unknown as Metrics;
}

function createMockEvent(
  overrides: Partial<APIGatewayProxyEventV2> = {},
): APIGatewayProxyEventV2 {
  return {
    headers: { "content-encoding": "gzip" },
    isBase64Encoded: true,
    body: "",
    requestContext: {} as never,
    routeKey: "",
    rawPath: "",
    rawQueryString: "",
    version: "2.0",
    ...overrides,
  } as APIGatewayProxyEventV2;
}

describe("decompressPayload", () => {
  let metrics: Metrics;

  beforeEach(() => {
    metrics = createMockMetrics();
  });

  describe("validateBinaryPrereqs", () => {
    it("should throw 400 when Content-Encoding header is missing", async () => {
      const event = createMockEvent({ headers: {} });
      await expect(
        decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        ),
      ).rejects.toThrow(HttpError);

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
        expect((err as HttpError).statusCode).toBe(400);
        expect((err as HttpError).message).toContain("Content-Encoding");
      }
    });

    it("should throw 400 when Content-Encoding is not gzip", async () => {
      const event = createMockEvent({
        headers: { "content-encoding": "deflate" },
      });
      await expect(
        decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        ),
      ).rejects.toThrow(HttpError);

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
      } catch (err) {
        expect((err as HttpError).statusCode).toBe(400);
      }
    });

    it("should throw 400 when body is not base64 encoded", async () => {
      const event = createMockEvent({ isBase64Encoded: false });
      await expect(
        decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        ),
      ).rejects.toThrow(HttpError);

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
      } catch (err) {
        expect((err as HttpError).statusCode).toBe(400);
        expect((err as HttpError).message).toContain("base64");
      }
    });
  });

  describe("decodeAndValidateGzip", () => {
    it("should throw 413 when compressed payload is too large", async () => {
      // Create a gzip buffer larger than maxBodyBytes
      const largePayload = Buffer.alloc(200).fill(0x1f);
      largePayload[0] = 0x1f;
      largePayload[1] = 0x8b;
      const event = createMockEvent({
        body: largePayload.toString("base64"),
      });

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 10, maxDecompressedBytes: 500_000 },
          metrics,
        );
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
        expect((err as HttpError).statusCode).toBe(413);
        expect((err as HttpError).message).toContain("too large");
      }
    });

    it("should throw 400 when data has invalid gzip magic bytes", async () => {
      const badData = Buffer.from([0x00, 0x00, 0x00, 0x00]);
      const event = createMockEvent({
        body: badData.toString("base64"),
      });

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
        expect((err as HttpError).statusCode).toBe(400);
        expect((err as HttpError).message).toContain("Invalid gzip");
      }
    });

    it("should accept valid gzip data with correct magic bytes", async () => {
      const payload = JSON.stringify({ test: "data" });
      const compressed = gzipSync(Buffer.from(payload));
      const event = createMockEvent({
        body: compressed.toString("base64"),
      });

      await decompressPayload(
        event,
        { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
        metrics,
      );

      expect(event.body).toBe(payload);
    });
  });

  describe("streamingGunzip", () => {
    it("should decompress a valid gzip payload", async () => {
      const payload = JSON.stringify({ hello: "world", number: 42 });
      const compressed = gzipSync(Buffer.from(payload));
      const event = createMockEvent({
        body: compressed.toString("base64"),
      });

      await decompressPayload(
        event,
        { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
        metrics,
      );

      expect(event.body).toBe(payload);
      expect(
        metrics.addMetric as ReturnType<typeof vi.fn>,
      ).toHaveBeenCalledWith("BinaryGzipPayloadReceived", MetricUnit.Count, 1);
    });

    it("should throw when decompressed size exceeds limit (zip bomb protection)", async () => {
      // Create a payload that compresses well but decompresses to > limit
      const largePayload = "A".repeat(10_000);
      const compressed = gzipSync(Buffer.from(largePayload));
      const event = createMockEvent({
        body: compressed.toString("base64"),
      });

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 100 }, // Very small decompressed limit
          metrics,
        );
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
        expect((err as HttpError).statusCode).toBe(400);
        expect((err as HttpError).message).toContain("exceeds limit");
      }
    });
  });

  describe("decompressPayload end-to-end", () => {
    it("should decompress and replace event.body with UTF-8 string", async () => {
      const payload = JSON.stringify({ fingerprint: "abc123" });
      const compressed = gzipSync(Buffer.from(payload));
      const event = createMockEvent({
        body: compressed.toString("base64"),
      });

      await decompressPayload(
        event,
        { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
        metrics,
      );

      expect(event.body).toBe(payload);
      const parsed = JSON.parse(event.body!);
      expect(parsed.fingerprint).toBe("abc123");
    });

    it("should let HttpError pass through from validation", async () => {
      const event = createMockEvent({ headers: {} });
      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
      }
    });

    it("should wrap generic decompression failure as HttpError 400", async () => {
      // Create a valid gzip payload but mock createGunzip to simulate failure
      const payload = JSON.stringify({ test: "data" });
      const { gzipSync } = await import("zlib");
      const compressed = gzipSync(Buffer.from(payload));

      // Corrupt the compressed data after the magic bytes (bytes 10+)
      // This produces a zlib data error that gets caught by the pipeline
      const corrupted = Buffer.from(compressed);
      for (let i = 10; i < corrupted.length; i++) {
        corrupted[i] = corrupted[i]! ^ 0xff;
      }

      const event = createMockEvent({
        body: corrupted.toString("base64"),
      });

      try {
        await decompressPayload(
          event,
          { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 },
          metrics,
        );
        expect.unreachable("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(HttpError);
        expect((err as HttpError).statusCode).toBe(400);
      }
    });
  });
});
