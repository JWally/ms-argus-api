/**
 * @fileoverview Middy middleware for the ingestion handler.
 * Provides body parsing for both JSON and gzip-compressed binary payloads.
 * @module handlers/ingestion/middleware
 */

import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import middy from "@middy/core";
import { HttpError } from "../../helpers/http-error";
import { decompressPayload } from "./gzip";

/**
 * Middy middleware that handles binary gzip-encoded payloads.
 *
 * For `application/octet-stream` content types:
 * - Validates Content-Encoding header includes "gzip"
 * - Decompresses the payload with size limits
 * - Replaces event.body with decompressed UTF-8 string
 *
 * For other content types:
 * - Only validates body size against maxBodyBytes limit
 *
 * @param config - Size limit configuration
 * @param config.maxBodyBytes - Maximum compressed body size in bytes
 * @param config.maxDecompressedBytes - Maximum decompressed size (prevents zip bombs)
 * @param metrics - Metrics instance for tracking payload types and errors
 * @returns Middy middleware object with `before` handler
 *
 * @throws {HttpError} 413 if payload exceeds size limits
 * @throws {HttpError} 400 if gzip decompression fails
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(binaryGzipBodyParser({ maxBodyBytes: 1024 * 100, maxDecompressedBytes: 1024 * 500 }, metrics));
 * ```
 */
export const binaryGzipBodyParser = (
  config: { maxBodyBytes: number; maxDecompressedBytes: number },
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const contentType = (event.headers["content-type"] ?? "").toLowerCase();
    if (!contentType.startsWith("application/octet-stream")) {
      if (Buffer.byteLength(event.body ?? "", "utf8") > config.maxBodyBytes) {
        metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
        throw new HttpError(413, "Request entity too large");
      }
      metrics.addMetric("JsonPayloadReceived", MetricUnit.Count, 1);
      return;
    }
    await decompressPayload(event, config, metrics);
  },
});

/**
 * Middy middleware that parses JSON request bodies for the /v1/collect endpoint.
 *
 * Only processes POST requests to /v1/collect. For matching requests:
 * - Parses JSON body and attaches to event.parsedBody
 * - Tracks invalid JSON payloads via metrics
 *
 * @param metrics - Metrics instance for tracking parse errors
 * @returns Middy middleware object with `before` handler
 *
 * @throws {HttpError} 400 if JSON parsing fails
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(jsonBodyParser(metrics));
 *
 * // In handler:
 * const payload = (event as any).parsedBody;
 * ```
 */
export const jsonBodyParser = (
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const method = event.requestContext.http.method;

    if (method !== "POST") {
      return;
    }

    if (event.rawPath !== "/v1/collect") {
      return;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (event as any).parsedBody = JSON.parse(event.body ?? "{}");
    } catch {
      metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
      throw new HttpError(400, "Invalid JSON payload");
    }
  },
});
