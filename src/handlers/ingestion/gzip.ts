import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { createGunzip } from "zlib";
import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { HttpError } from "../../helpers/http-error";

const streamingGunzip = async (
  gzipBuffer: Buffer,
  maxBytes: number,
): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  const gunzip = createGunzip();

  gunzip.on("data", (chunk: Buffer) => {
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      gunzip.destroy(
        new Error(
          `Decompressed size exceeds limit (${maxBytes} bytes) - aborting`,
        ),
      );
      return;
    }
    chunks.push(chunk);
  });

  try {
    await pipeline(Readable.from(gzipBuffer), gunzip);
    return Buffer.concat(chunks);
  } catch (err) {
    if (err instanceof Error && err.message.includes("exceeds limit")) {
      throw err;
    }
    throw new Error("Failed to decompress gzip payload");
  }
};

function validateBinaryPrereqs(
  event: APIGatewayProxyEventV2,
  metrics: Metrics,
): void {
  const contentEncoding = (
    event.headers["content-encoding"] ?? ""
  ).toLowerCase();
  if (!contentEncoding.includes("gzip")) {
    metrics.addMetric("MissingGzipEncoding", MetricUnit.Count, 1);
    throw new HttpError(400, "Binary payload requires Content-Encoding: gzip");
  }
  if (!event.isBase64Encoded) {
    throw new HttpError(
      400,
      "Binary payload must be base64-encoded by API Gateway",
    );
  }
}

function decodeAndValidateGzip(
  rawBody: string,
  maxBodyBytes: number,
  metrics: Metrics,
): Buffer {
  const gzipBuffer = Buffer.from(rawBody, "base64");
  if (gzipBuffer.length > maxBodyBytes) {
    metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
    throw new HttpError(413, "Compressed payload too large");
  }
  if (
    gzipBuffer.length < 2 ||
    gzipBuffer[0] !== 0x1f ||
    gzipBuffer[1] !== 0x8b
  ) {
    metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
    throw new HttpError(400, "Invalid gzip data");
  }
  return gzipBuffer;
}

export async function decompressPayload(
  event: APIGatewayProxyEventV2,
  config: { maxBodyBytes: number; maxDecompressedBytes: number },
  metrics: Metrics,
): Promise<void> {
  validateBinaryPrereqs(event, metrics);
  const gzipBuffer = decodeAndValidateGzip(
    event.body ?? "",
    config.maxBodyBytes,
    metrics,
  );
  try {
    const decompressed = await streamingGunzip(
      gzipBuffer,
      config.maxDecompressedBytes,
    );
    event.body = decompressed.toString("utf-8");
    metrics.addMetric("BinaryGzipPayloadReceived", MetricUnit.Count, 1);
  } catch (err) {
    if (err instanceof HttpError) throw err;
    metrics.addMetric("GzipDecompressionFailed", MetricUnit.Count, 1);
    const message =
      err instanceof Error && err.message.includes("exceeds limit")
        ? err.message
        : "Failed to decompress gzip payload";
    throw new HttpError(400, message);
  }
}
