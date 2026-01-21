// src/handlers/ingestion.test.ts
// AR-90: Tests for ingestion handler with binary gzip compression support
// AR-127: Added warmup middleware tests
/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { gzipSync } from "zlib";

// Set environment variables BEFORE any module imports
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-ingestion-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SQS_QUEUE_URL =
    "https://sqs.us-east-1.amazonaws.com/123456789/test-queue";
  // AR-139: Payload archiving config
  process.env.PAYLOAD_ARCHIVE_BUCKET = "test-archive-bucket";
  process.env.PAYLOAD_ARCHIVE_SAMPLE_RATE = "1.0";
});

import { mockClient } from "aws-sdk-client-mock";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  Context,
} from "aws-lambda";

// Mock AWS SDK clients
const sqsMock = mockClient(SQSClient);
const s3Mock = mockClient(S3Client); // AR-139

// Import handler after mocking
import { handler, archivePayload } from "./ingestion";

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
    s3Mock.reset(); // AR-139
    s3Mock.on(PutObjectCommand).resolves({}); // AR-139
    vi.clearAllMocks();
  });

  // Helper to create API Gateway event
  const createApiEvent = (
    body: string,
    options: {
      method?: string;
      path?: string;
      origin?: string;
      contentType?: string;
      contentEncoding?: string;
      isBase64Encoded?: boolean;
    } = {},
  ): APIGatewayProxyEventV2 => ({
    version: "2.0",
    routeKey: "POST /v1/collect",
    rawPath: options.path ?? "/v1/collect",
    rawQueryString: "",
    headers: {
      "content-type": options.contentType ?? "application/json",
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

  // Helper: Simulate API Gateway encoding of browser's raw binary gzip
  // AR-90: Browser sends raw gzip bytes with Content-Type: application/octet-stream
  // API Gateway receives binary, base64-encodes it, sets isBase64Encoded=true
  // Lambda receives: base64(gzip(json)) with isBase64Encoded=true
  const simulateBinaryGzipBody = (payload: object): string => {
    const jsonString = JSON.stringify(payload);
    const gzipped = gzipSync(Buffer.from(jsonString)); // Raw gzip bytes
    return gzipped.toString("base64"); // API Gateway base64 encodes binary
  };

  // ==================== AR-90: BINARY GZIP COMPRESSION TESTS ====================
  // New simplified flow: browser sends raw gzip bytes, API Gateway base64 encodes once
  describe("binary gzip compression support (AR-90)", () => {
    it("should decompress binary gzip payload with application/octet-stream", async () => {
      const payload = createValidPayload("binary-gzip-session-1");
      const body = simulateBinaryGzipBody(payload);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify SQS was called with decompressed payload
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("binary-gzip-session-1");
    });

    it("should handle large binary gzip payload (>64KB uncompressed)", async () => {
      // Create a payload that would exceed 64KB uncompressed
      const largeData = {
        session_id: "large-binary-payload-session",
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

      const body = simulateBinaryGzipBody(largeData);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify the full payload was sent to SQS
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("large-binary-payload-session");
      expect(sentBody.fingerprint.loose.canvas2d.data.length).toBe(30000);
    });

    it("should return 400 for invalid binary gzip data", async () => {
      // Send garbage bytes that aren't valid gzip
      const invalidData = Buffer.from("this is not gzip data").toString(
        "base64",
      );

      const event = createApiEvent(invalidData, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("Invalid gzip");
    });

    it("should return 400 for binary gzip payload with invalid JSON inside", async () => {
      // Valid gzip but invalid JSON content
      const invalidJson = "{ this is not valid json }";
      const gzipped = gzipSync(Buffer.from(invalidJson));
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      expect(parsedBody.error).toContain("Invalid JSON");
    });

    it("should preserve sigint data in binary gzipped payload", async () => {
      const payload = {
        session_id: "sigint-binary-test-session",
        fingerprint: { hashes: { stable: "abc" } },
        sigint: {
          tls: { ja4: "t13d1516h2_8daaf6152771_b0da82dd1658" },
          tcp: { ttl: 64, windowSize: 65535 },
        },
      };

      const body = simulateBinaryGzipBody(payload);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
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

    it("should handle empty binary gzipped payload", async () => {
      const gzipped = gzipSync(Buffer.from(""));
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Empty payload should fail JSON parsing
      expect(result.statusCode).toBe(400);
    });

    it("should handle gzip Content-Encoding case-insensitively", async () => {
      const payload = createValidPayload("case-insensitive-binary-session");
      const body = simulateBinaryGzipBody(payload);

      // Test with uppercase "GZIP"
      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "GZIP",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should reject binary gzip payload that exceeds size limit after decompression", async () => {
      // Create a payload that compresses small but decompresses huge (zip bomb defense)
      // AR-149: Default limit increased to 2MB
      const hugePayload = {
        session_id: "zipbomb-binary-test",
        data: "A".repeat(2.5 * 1024 * 1024), // 2.5MB of 'A' characters - exceeds 2MB limit
      };

      const jsonString = JSON.stringify(hugePayload);
      expect(jsonString.length).toBeGreaterThan(2 * 1024 * 1024); // Verify exceeds limit

      const gzipped = gzipSync(Buffer.from(jsonString));
      expect(gzipped.length).toBeLessThan(10 * 1024); // Compresses well

      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Should reject oversized decompressed content (zip bomb defense)
      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      // AR-136: Now includes size limit in message
      expect(parsedBody.error).toContain("exceeds limit");
    });

    // AR-136: ZIP bomb vulnerability tests - streaming decompression with early abort
    // AR-149: Default limit increased to 2MB
    it("should include size limit in error message when decompression exceeds limit (AR-136 AC2)", async () => {
      const hugePayload = {
        session_id: "zipbomb-error-message-test",
        data: "B".repeat(2.5 * 1024 * 1024), // Exceeds 2MB limit
      };

      const gzipped = gzipSync(Buffer.from(JSON.stringify(hugePayload)));
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      // AC2: Error message should include size limit
      expect(parsedBody.error).toMatch(/2097152|2MB/); // 2MB or 2097152 bytes
    });

    it("should abort decompression early without allocating full buffer (AR-136 AC1)", async () => {
      // This test verifies behavior - actual memory behavior tested via integration
      // Create payload that would expand to several MB
      // AR-149: Default limit increased to 2MB
      const largeExpandingPayload = {
        session_id: "early-abort-test",
        // Repetitive data compresses well, expands to >2MB
        data: "ABCDEFGHIJ".repeat(300000), // ~3MB of text
      };

      const gzipped = gzipSync(
        Buffer.from(JSON.stringify(largeExpandingPayload)),
      );
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Should reject with clear error - streaming should abort early
      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      expect(parsedBody.error).toContain("exceeds");
    });

    it("should successfully decompress payloads just under the limit (AR-136 AC4)", async () => {
      // AR-149: Default limit increased to 2MB
      // 1.5MB is safely under 2MB limit - should succeed
      const nearLimitPayload = {
        session_id: "near-limit-success-test",
        data: "X".repeat(1.5 * 1024 * 1024), // 1.5MB, safely under 2MB
      };

      const gzipped = gzipSync(Buffer.from(JSON.stringify(nearLimitPayload)));
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Should succeed - payload is under limit
      expect(result.statusCode).toBe(204);
    });

    it("should require Content-Encoding: gzip for binary payloads", async () => {
      // Binary payload without gzip encoding should fail
      const payload = createValidPayload("no-encoding-session");
      const body = simulateBinaryGzipBody(payload);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        // No contentEncoding - should fail
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      // Should reject - binary without gzip encoding is invalid
      expect(result.statusCode).toBe(400);
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
      // AR-149: Default limit increased to 256KB, test with larger payload
      const oversizedPayload = {
        session_id: "test",
        data: "x".repeat(300 * 1024), // 300KB > 256KB default limit
      };

      const event = createApiEvent(JSON.stringify(oversizedPayload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(413);
    });
  });

  // AR-127: Warmup middleware tests
  describe("warmup middleware (AR-127)", () => {
    it("should short-circuit warmup events with serverless-plugin-warmup source", async () => {
      // Warmup event from serverless-plugin-warmup
      const warmupEvent = {
        source: "serverless-plugin-warmup",
      } as unknown as APIGatewayProxyEventV2;

      const result = await handler(warmupEvent, mockContext);

      // Warmup events return early - no SQS call
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(0);

      // @middy/warmup returns "warmup" string when short-circuiting
      expect(result).toBe("warmup");
    });

    it("should process normal events (non-warmup) as usual", async () => {
      const payload = createValidPayload("normal-event-after-warmup-test");
      const event = createApiEvent(JSON.stringify(payload));

      const result = asResult(await handler(event, mockContext));

      // Normal event should be processed
      expect(result.statusCode).toBe(204);

      // SQS should be called
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("normal-event-after-warmup-test");
    });

    it("should not call SQS for warmup events", async () => {
      // Warmup event
      const warmupEvent = {
        source: "serverless-plugin-warmup",
      } as unknown as APIGatewayProxyEventV2;

      await handler(warmupEvent, mockContext);

      // Verify no SQS call was made
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(0);
    });
  });

  // AR-184: Schema version detection and metrics
  describe("schema version detection (AR-184)", () => {
    it("should accept v1 format payload (session_id at root, fingerprint object)", async () => {
      const v1Payload = {
        session_id: "v1-test-session",
        fingerprint: {
          stable_hash: "abc123",
          fuzzy_hash: "def456",
          canvas_hash: "canvas_hash",
        },
        sigint: {
          tlsFingerprint: { ja4: "test_ja4" },
        },
      };
      const event = createApiEvent(JSON.stringify(v1Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify SQS payload
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.session_id).toBe("v1-test-session");
    });

    it("should accept v2 format payload (identifiers, device sections)", async () => {
      const v2Payload = {
        identifiers: {
          session_id: "v2-test-session",
          evercookie_id: "ec_123",
        },
        device: {
          hashes: {
            stable: "abc123",
            fuzzy: "def456",
          },
          user_agent: "Mozilla/5.0",
          platform: "Win32",
          language: "en-US",
          languages: ["en-US"],
          screen_width: 1920,
          screen_height: 1080,
          color_depth: 24,
          pixel_ratio: 1,
          timezone_offset: -300,
          timezone_name: "America/Chicago",
          webdriver: false,
          headless_signals: [],
        },
      };
      const event = createApiEvent(JSON.stringify(v2Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Verify SQS payload preserves structure
      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe("v2-test-session");
      expect(sentBody.device.hashes.stable).toBe("abc123");
    });

    it("should extract session_id from v2 identifiers.session_id", async () => {
      const v2Payload = {
        identifiers: {
          session_id: "v2-extracted-session",
        },
        device: {
          hashes: { stable: "a", fuzzy: "b" },
          user_agent: "test",
          platform: "test",
          language: "en",
          languages: ["en"],
          screen_width: 1920,
          screen_height: 1080,
          color_depth: 24,
          pixel_ratio: 1,
          timezone_offset: 0,
          timezone_name: "UTC",
          webdriver: false,
          headless_signals: [],
        },
      };
      const event = createApiEvent(JSON.stringify(v2Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should return 400 for v2 payload missing identifiers.session_id", async () => {
      const invalidV2 = {
        identifiers: {
          // missing session_id
          evercookie_id: "ec_123",
        },
        device: {
          hashes: { stable: "a", fuzzy: "b" },
        },
      };
      const event = createApiEvent(JSON.stringify(invalidV2));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("session_id");
    });
  });

  // AR-139: Payload archiving tests
  describe("payload archiving (AR-139)", () => {
    it("should archive payload with correct Hive-partitioned S3 key format", async () => {
      const sessionId = "archive-test-session-123";
      const payload = { session_id: sessionId, data: "test-data" };

      await archivePayload(sessionId, payload);

      // Verify S3 was called
      const s3Calls = s3Mock.commandCalls(PutObjectCommand);
      expect(s3Calls.length).toBe(1);

      // Verify key format: year=YYYY/month=MM/day=DD/hour=HH/{sessionId}.json.gz
      const key = s3Calls[0].args[0].input.Key!;
      expect(key).toMatch(
        /^year=\d{4}\/month=\d{2}\/day=\d{2}\/hour=\d{2}\/archive-test-session-123\.json\.gz$/,
      );
    });

    it("should compress payload with gzip", async () => {
      const sessionId = "gzip-test-session";
      const payload = { session_id: sessionId, test: "data" };

      await archivePayload(sessionId, payload);

      const s3Calls = s3Mock.commandCalls(PutObjectCommand);
      expect(s3Calls.length).toBe(1);

      // Verify ContentEncoding is gzip
      expect(s3Calls[0].args[0].input.ContentEncoding).toBe("gzip");
      expect(s3Calls[0].args[0].input.ContentType).toBe("application/json");

      // Verify body is a Buffer (gzipped content)
      expect(s3Calls[0].args[0].input.Body).toBeInstanceOf(Buffer);
    });

    it("should log error but not throw when S3 upload fails", async () => {
      // Make S3 fail
      s3Mock.reset();
      s3Mock.on(PutObjectCommand).rejects(new Error("S3 unavailable"));

      // Should not throw
      await expect(
        archivePayload("error-test-session", { data: "test" }),
      ).resolves.toBeUndefined();
    });

    it("should call archivePayload during successful ingestion", async () => {
      const payload = createValidPayload("archive-integration-test");
      const event = createApiEvent(JSON.stringify(payload));

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      // Wait a tick for async archive to complete
      await new Promise((resolve) => setTimeout(resolve, 10));

      // S3 should have been called (archive is async but we give it time)
      const s3Calls = s3Mock.commandCalls(PutObjectCommand);
      expect(s3Calls.length).toBeGreaterThanOrEqual(1);
    });
  });
});
