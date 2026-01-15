// src/handlers/ingestion.test.ts
// AR-87: Tests for ingestion handler with gzip compression support

import { describe, it, expect, beforeEach, vi } from "vitest";
import { gzipSync } from "zlib";

// Set environment variables BEFORE any module imports
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-ingestion-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SQS_QUEUE_URL =
    "https://sqs.us-east-1.amazonaws.com/123456789/test-queue";
});

import { mockClient } from "aws-sdk-client-mock";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  Context,
} from "aws-lambda";

// Mock AWS SDK clients
const sqsMock = mockClient(SQSClient);

// Import handler after mocking
import { handler } from "./ingestion";

// Helper to cast result
const asResult = (result: unknown): APIGatewayProxyStructuredResultV2 =>
  result as APIGatewayProxyStructuredResultV2;

describe("ingestion handler", () => {
  const mockContext: Context = {
    callbackWaitsForEmptyEventLoop: false,
    functionName: "test-function",
    functionVersion: "1",
    invokedFunctionArn: "arn:aws:lambda:us-east-1:123456789:function:test",
    memoryLimitInMB: "256",
    awsRequestId: "test-request-id",
    logGroupName: "/aws/lambda/test",
    logStreamName: "2025/01/01/[$LATEST]test",
    getRemainingTimeInMillis: () => 30000,
    done: () => {},
    fail: () => {},
    succeed: () => {},
  };

  beforeEach(() => {
    sqsMock.reset();
    sqsMock.on(SendMessageCommand).resolves({});
    vi.clearAllMocks();
  });

  // Helper to create API Gateway event
  const createApiEvent = (
    body: string,
    options: {
      method?: string;
      path?: string;
      origin?: string;
      contentEncoding?: string;
      isBase64Encoded?: boolean;
    } = {},
  ): APIGatewayProxyEventV2 => ({
    version: "2.0",
    routeKey: "POST /v1/collect",
    rawPath: options.path ?? "/v1/collect",
    rawQueryString: "",
    headers: {
      "content-type": "application/json",
      ...(options.origin ? { origin: options.origin } : {}),
      ...(options.contentEncoding
        ? { "content-encoding": options.contentEncoding }
        : {}),
    },
    requestContext: {
      accountId: "123456789",
      apiId: "test-api",
      domainName: "api.example.com",
      domainPrefix: "api",
      http: {
        method: options.method ?? "POST",
        path: options.path ?? "/v1/collect",
        protocol: "HTTP/1.1",
        sourceIp: "127.0.0.1",
        userAgent: "test-agent",
      },
      requestId: "test-request",
      routeKey: "POST /v1/collect",
      stage: "$default",
      time: "01/Jan/2025:00:00:00 +0000",
      timeEpoch: 1704067200000,
    },
    body,
    isBase64Encoded: options.isBase64Encoded ?? false,
  });

  // Helper to create valid fingerprint payload
  const createValidPayload = (sessionId = "test-session-123") => ({
    session_id: sessionId,
    tenant_id: "demo",
    fingerprint: {
      hashes: { stable: "abc123", fuzzy: "def456" },
      loose: { screen: { width: 1920, height: 1080 } },
    },
  });

  describe("basic functionality", () => {
    it("should accept valid uncompressed JSON payload", async () => {
      const payload = createValidPayload();
      const event = createApiEvent(JSON.stringify(payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should return 400 for missing session_id", async () => {
      const event = createApiEvent(JSON.stringify({ fingerprint: {} }));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("session_id");
    });

    it("should return 400 for invalid JSON", async () => {
      const event = createApiEvent("{ invalid json }");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("Invalid JSON");
    });
  });

  // ==================== AR-87: GZIP COMPRESSION TESTS ====================
  describe("gzip compression support (AR-87)", () => {
    it("should decompress gzip payload with Content-Encoding: gzip header", async () => {
      const payload = createValidPayload("gzip-session-1");
      const jsonString = JSON.stringify(payload);
      const gzipped = gzipSync(Buffer.from(jsonString));
      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify SQS was called with decompressed payload
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("gzip-session-1");
    });

    it("should handle large gzip compressed payload (>64KB uncompressed)", async () => {
      // Create a payload that would exceed 64KB uncompressed
      const largeData = {
        session_id: "large-payload-session",
        tenant_id: "demo",
        fingerprint: {
          hashes: { stable: "abc", fuzzy: "def" },
          loose: {
            // Large nested data that compresses well
            canvas2d: { $hash: "canvas-hash", data: "x".repeat(30000) },
            webgl: { $hash: "webgl-hash", data: "y".repeat(30000) },
            audio: { $hash: "audio-hash", data: "z".repeat(30000) },
          },
        },
      };

      const jsonString = JSON.stringify(largeData);
      expect(jsonString.length).toBeGreaterThan(64 * 1024); // Verify it's > 64KB

      const gzipped = gzipSync(Buffer.from(jsonString));
      expect(gzipped.length).toBeLessThan(64 * 1024); // Verify compressed is < 64KB

      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify the full payload was sent to SQS
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("large-payload-session");
      expect(sentBody.fingerprint.loose.canvas2d.data.length).toBe(30000);
    });

    it("should return 400 for invalid gzip data", async () => {
      // Send base64-encoded garbage that isn't valid gzip
      const invalidGzip = Buffer.from("this is not gzip data").toString(
        "base64",
      );

      const event = createApiEvent(invalidGzip, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("decompress");
    });

    it("should return 400 for gzip payload with invalid JSON inside", async () => {
      // Valid gzip but invalid JSON content
      const invalidJson = "{ this is not valid json }";
      const gzipped = gzipSync(Buffer.from(invalidJson));
      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("Invalid JSON");
    });

    it("should handle uncompressed payload when Content-Encoding is not gzip", async () => {
      // Backward compatibility: no Content-Encoding header = uncompressed
      const payload = createValidPayload("uncompressed-session");
      const event = createApiEvent(JSON.stringify(payload));

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("uncompressed-session");
    });

    it("should handle gzip with isBase64Encoded false (raw binary not supported)", async () => {
      // API Gateway should always base64 encode binary content
      // If it doesn't, we should handle gracefully
      const payload = createValidPayload();
      const gzipped = gzipSync(Buffer.from(JSON.stringify(payload)));

      // Raw binary (not base64) - this shouldn't happen but test defensive handling
      const event = createApiEvent(gzipped.toString("binary"), {
        contentEncoding: "gzip",
        isBase64Encoded: false, // Not base64 encoded
      });

      const result = asResult(await handler(event, mockContext));

      // Should return error since we can't decompress non-base64 gzip
      expect(result.statusCode).toBe(400);
    });

    it("should preserve sigint data in gzipped payload", async () => {
      const payload = {
        session_id: "sigint-test-session",
        tenant_id: "demo",
        fingerprint: { hashes: { stable: "abc" } },
        sigint: {
          tls: { ja4: "t13d1516h2_8daaf6152771_b0da82dd1658" },
          tcp: { ttl: 64, windowSize: 65535 },
        },
      };

      const gzipped = gzipSync(Buffer.from(JSON.stringify(payload)));
      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.sigint).toBeDefined();
      expect(sentBody.sigint.tls.ja4).toBe(
        "t13d1516h2_8daaf6152771_b0da82dd1658",
      );
    });

    it("should handle empty gzipped payload", async () => {
      const gzipped = gzipSync(Buffer.from(""));
      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Empty payload should fail JSON parsing
      expect(result.statusCode).toBe(400);
    });

    it("should handle gzip Content-Encoding case-insensitively", async () => {
      const payload = createValidPayload("case-insensitive-session");
      const gzipped = gzipSync(Buffer.from(JSON.stringify(payload)));
      const base64Body = gzipped.toString("base64");

      // Test with uppercase "GZIP"
      const event = createApiEvent(base64Body, {
        contentEncoding: "GZIP",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should reject gzip payload that exceeds size limit after decompression", async () => {
      // Create a payload that compresses small but decompresses huge (zip bomb defense)
      // Use highly compressible data - must exceed MAX_DECOMPRESSED_SIZE (512KB)
      const hugePayload = {
        session_id: "zipbomb-test",
        data: "A".repeat(600 * 1024), // 600KB of 'A' characters - exceeds 512KB limit
      };

      const jsonString = JSON.stringify(hugePayload);
      expect(jsonString.length).toBeGreaterThan(512 * 1024); // Verify exceeds limit

      const gzipped = gzipSync(Buffer.from(jsonString));
      // Compresses extremely well - ~600 bytes for 600KB of repeated chars
      expect(gzipped.length).toBeLessThan(10 * 1024);

      const base64Body = gzipped.toString("base64");

      const event = createApiEvent(base64Body, {
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Should reject oversized decompressed content (zip bomb defense)
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("too large");
    });
  });

  describe("HTTP methods and routing", () => {
    it("should return 204 for OPTIONS (CORS preflight)", async () => {
      const event = createApiEvent("", {
        method: "OPTIONS",
        origin: "https://test.com",
      });
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should return 405 for GET method", async () => {
      const event = createApiEvent("", { method: "GET" });
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(405);
    });

    it("should return 404 for wrong path", async () => {
      const payload = createValidPayload();
      const event = createApiEvent(JSON.stringify(payload), {
        path: "/v1/wrong",
      });
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(404);
    });

    it("should return 200 for health check", async () => {
      const event = createApiEvent("", { path: "/health", method: "GET" });
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body ?? "");
      expect(body.status).toBe("healthy");
    });
  });

  describe("CORS headers", () => {
    it("should include CORS headers when origin is provided", async () => {
      const payload = createValidPayload();
      const event = createApiEvent(JSON.stringify(payload), {
        origin: "https://app.example.com",
      });
      const result = asResult(await handler(event, mockContext));

      expect(result.headers?.["Access-Control-Allow-Origin"]).toBe(
        "https://app.example.com",
      );
    });
  });

  describe("error handling", () => {
    it("should return 503 when SQS fails", async () => {
      sqsMock.on(SendMessageCommand).rejects(new Error("SQS unavailable"));

      const payload = createValidPayload();
      const event = createApiEvent(JSON.stringify(payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(503);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Service temporarily unavailable");
    });

    it("should return 413 for oversized uncompressed payload", async () => {
      const oversizedPayload = {
        session_id: "test",
        data: "x".repeat(70 * 1024), // 70KB > 64KB limit
      };

      const event = createApiEvent(JSON.stringify(oversizedPayload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(413);
    });
  });
});
