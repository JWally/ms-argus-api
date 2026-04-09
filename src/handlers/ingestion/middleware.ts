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
import { getEcdhKeys } from "../../helpers/get-ecdh-keys";
import {
  decryptArgusPayload,
  decryptIntegrityPayload,
} from "../../helpers/ecdh-decrypt";

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
async function handleEcdhPayload(
  event: APIGatewayProxyEventV2,
  clientPubKey: string,
  metrics: Metrics,
): Promise<void> {
  const keys = await getEcdhKeys();
  if (!keys) {
    metrics.addMetric("EcdhNotConfigured", MetricUnit.Count, 1);
    throw new HttpError(503, "Encrypted ingestion not configured");
  }

  const isIntegrity = event.rawPath === "/v1/integrity-collect";
  let parsed: unknown | null;

  if (isIntegrity) {
    // Integrity payloads have an inner XOR scramble layer.
    // Key = h2Token (from X-Argus-Session) + deploySecret (from env).
    const h2Token = event.headers["x-argus-session"] ?? "";
    const deploySecret = process.env.INTEGRITY_DEPLOY_SECRET ?? "";
    const innerKey = h2Token + deploySecret;

    parsed = await decryptIntegrityPayload({
      body: event.body ?? "",
      isBase64Encoded: event.isBase64Encoded,
      clientPubKey,
      keys,
      innerKey,
    });
    if (!parsed) {
      metrics.addMetric("IntegrityDecryptFailed", MetricUnit.Count, 1);
      throw new HttpError(400, "Integrity payload decryption failed");
    }
    metrics.addMetric("IntegrityPayloadReceived", MetricUnit.Count, 1);
  } else {
    parsed = await decryptArgusPayload(
      event.body ?? "",
      event.isBase64Encoded,
      clientPubKey,
      keys,
    );
    if (!parsed) {
      metrics.addMetric("EcdhDecryptFailed", MetricUnit.Count, 1);
      throw new HttpError(400, "Payload decryption failed");
    }
    metrics.addMetric("EcdhPayloadReceived", MetricUnit.Count, 1);
  }

  // Replace body with JSON string so jsonBodyParser can parse it normally
  event.body = JSON.stringify(parsed);
  event.isBase64Encoded = false;
}

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

    // ECDH-encrypted argus-web payload: X-Argus-Origin header carries client pubkey
    const clientPubKey = event.headers["x-argus-origin"];
    if (clientPubKey) {
      await handleEcdhPayload(event, clientPubKey, metrics);
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

    if (
      event.rawPath !== "/v1/collect" &&
      event.rawPath !== "/v1/integrity-collect"
    ) {
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
