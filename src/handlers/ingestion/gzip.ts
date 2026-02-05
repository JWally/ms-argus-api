/**
 * @fileoverview Gzip decompression utilities for the ingestion handler.
 * Provides streaming decompression with size limits to prevent zip bomb attacks.
 * @module handlers/ingestion/gzip
 */

import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { createGunzip } from "zlib";
import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { HttpError } from "../../helpers/http-error";

/**
 * Decompresses a gzip buffer using streaming with a size limit.
 *
 * Uses Node.js streams to decompress incrementally, aborting immediately
 * if the decompressed size exceeds the limit. This prevents zip bomb attacks
 * where a small compressed payload expands to gigabytes.
 *
 * @param gzipBuffer - Compressed gzip data
 * @param maxBytes - Maximum allowed decompressed size in bytes
 * @returns Decompressed data as a Buffer
 *
 * @throws {Error} If decompressed size exceeds maxBytes
 * @throws {Error} If gzip decompression fails
 *
 * @internal
 */
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

/**
 * Validates prerequisites for binary payload processing.
 *
 * Ensures the request has:
 * - Content-Encoding header containing "gzip"
 * - Base64-encoded body (handled by API Gateway)
 *
 * @param event - API Gateway proxy event
 * @param metrics - Metrics instance for tracking validation failures
 *
 * @throws {HttpError} 400 if Content-Encoding is missing or body isn't base64
 *
 * @internal
 */
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

/**
 * Decodes base64 body and validates gzip magic bytes.
 *
 * Checks for the gzip magic number (0x1F 0x8B) to detect invalid data
 * before attempting decompression.
 *
 * @param rawBody - Base64-encoded request body
 * @param maxBodyBytes - Maximum compressed size in bytes
 * @param metrics - Metrics instance for tracking validation failures
 * @returns Decoded gzip buffer ready for decompression
 *
 * @throws {HttpError} 413 if compressed payload exceeds size limit
 * @throws {HttpError} 400 if data doesn't have valid gzip magic bytes
 *
 * @internal
 */
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

/**
 * Decompresses a gzip-encoded API Gateway event body in place.
 *
 * Orchestrates the full decompression pipeline:
 * 1. Validates Content-Encoding and base64 encoding
 * 2. Decodes and validates gzip magic bytes
 * 3. Streams decompression with size limit
 * 4. Replaces event.body with decompressed UTF-8 string
 *
 * @param event - API Gateway proxy event (body will be mutated)
 * @param config - Size limit configuration
 * @param config.maxBodyBytes - Maximum compressed body size
 * @param config.maxDecompressedBytes - Maximum decompressed size
 * @param metrics - Metrics for tracking decompression outcomes
 *
 * @throws {HttpError} 400 for invalid gzip or decompression failure
 * @throws {HttpError} 413 for oversized payloads
 *
 * @example
 * ```typescript
 * await decompressPayload(event, { maxBodyBytes: 100_000, maxDecompressedBytes: 500_000 }, metrics);
 * const payload = JSON.parse(event.body); // Now decompressed
 * ```
 */
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
