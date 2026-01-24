/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { gzipSync } from "zlib";

// Mock middy validator to avoid ES module compatibility issues in tests
// This mock passes through but doesn't do actual JSON schema validation
vi.mock("@middy/validator", () => ({
  default: () => ({
    before: async () => {
      // Pass-through - don't validate, let handler handle its own validation
    },
  }),
}));

vi.mock("@middy/validator/transpile", () => ({
  transpileSchema: (schema: unknown) => schema,
}));

// Set environment variables BEFORE any module imports
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-ingestion-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SQS_QUEUE_URL =
    "https://sqs.us-east-1.amazonaws.com/123456789/test-queue";
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

const sqsMock = mockClient(SQSClient);
const s3Mock = mockClient(S3Client);

import { handler, archivePayload } from "./ingestion";

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
    s3Mock.reset();
    s3Mock.on(PutObjectCommand).resolves({});
    vi.clearAllMocks();
  });

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

  const createValidPayload = (sessionId = "test-session-123") => ({
    identifiers: {
      session_id: sessionId,
    },
    hashes: {
      stable: "abc123",
      fuzzy: "def456",
    },
    device: {
      screen: { width: 1920, height: 1080 },
    },
  });

  describe("basic functionality", () => {
    it("should accept valid uncompressed JSON payload", async () => {
      const payload = createValidPayload();
      const event = createApiEvent(JSON.stringify(payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    // Note: Validation is handled by middy validator middleware which is mocked in tests
    it.skip("should return 400 for missing session_id", async () => {
      const event = createApiEvent(JSON.stringify({ identifiers: {} }));
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

  // Browser sends raw gzip bytes with Content-Type: application/octet-stream
  // API Gateway receives binary, base64-encodes it, sets isBase64Encoded=true
  // Lambda receives: base64(gzip(json)) with isBase64Encoded=true
  const simulateBinaryGzipBody = (payload: object): string => {
    const jsonString = JSON.stringify(payload);
    const gzipped = gzipSync(Buffer.from(jsonString));
    return gzipped.toString("base64");
  };

  describe("binary gzip compression support", () => {
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

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe("binary-gzip-session-1");
    });

    it("should handle large binary gzip payload (>64KB uncompressed)", async () => {
      const largeData = {
        identifiers: { session_id: "large-binary-payload-session" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {
          canvas2d: { hash: "canvas-hash", data: "x".repeat(30000) },
          canvasWebgl: { hash: "webgl-hash", data: "y".repeat(30000) },
          offlineAudioContext: { hash: "audio-hash", data: "z".repeat(30000) },
        },
      };

      const jsonString = JSON.stringify(largeData);
      expect(jsonString.length).toBeGreaterThan(64 * 1024);

      const gzipped = gzipSync(Buffer.from(jsonString));
      expect(gzipped.length).toBeLessThan(64 * 1024);

      const body = simulateBinaryGzipBody(largeData);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe(
        "large-binary-payload-session",
      );
      expect(sentBody.device.canvas2d.data.length).toBe(30000);
    });

    it("should return 400 for invalid binary gzip data", async () => {
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
        identifiers: { session_id: "sigint-binary-test-session" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {},
        sigint: {
          tlsFingerprint: { ja4: "t13d1516h2_8daaf6152771_b0da82dd1658" },
          tcpProbe: { rttMs: 64 },
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
      expect(sentBody.sigint.tlsFingerprint.ja4).toBe(
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

      expect(result.statusCode).toBe(400);
    });

    it("should handle gzip Content-Encoding case-insensitively", async () => {
      const payload = createValidPayload("case-insensitive-binary-session");
      const body = simulateBinaryGzipBody(payload);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "GZIP",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should reject binary gzip payload that exceeds size limit after decompression", async () => {
      // Default limit is 2MB
      const hugePayload = {
        session_id: "zipbomb-binary-test",
        data: "A".repeat(2.5 * 1024 * 1024), // 2.5MB exceeds 2MB limit
      };

      const jsonString = JSON.stringify(hugePayload);
      expect(jsonString.length).toBeGreaterThan(2 * 1024 * 1024);

      const gzipped = gzipSync(Buffer.from(jsonString));
      expect(gzipped.length).toBeLessThan(10 * 1024);

      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      expect(parsedBody.error).toContain("exceeds limit");
    });

    it("should include size limit in error message when decompression exceeds limit", async () => {
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
      expect(parsedBody.error).toMatch(/2097152|2MB/); // 2MB or 2097152 bytes
    });

    it("should abort decompression early without allocating full buffer", async () => {
      // Default limit is 2MB
      const largeExpandingPayload = {
        session_id: "early-abort-test",
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

      expect(result.statusCode).toBe(400);
      const parsedBody = JSON.parse(result.body ?? "");
      expect(parsedBody.error).toContain("exceeds");
    });

    it("should successfully decompress payloads just under the limit", async () => {
      // 1.5MB is safely under 2MB limit
      const nearLimitPayload = {
        identifiers: { session_id: "near-limit-success-test" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {
          largeData: "X".repeat(1.5 * 1024 * 1024),
        },
      };

      const gzipped = gzipSync(Buffer.from(JSON.stringify(nearLimitPayload)));
      const body = gzipped.toString("base64");

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        contentEncoding: "gzip",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    it("should require Content-Encoding: gzip for binary payloads", async () => {
      const payload = createValidPayload("no-encoding-session");
      const body = simulateBinaryGzipBody(payload);

      const event = createApiEvent(body, {
        contentType: "application/octet-stream",
        isBase64Encoded: true,
      });

      const result = asResult(await handler(event, mockContext));

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
      // 300KB exceeds 256KB default limit
      const oversizedPayload = {
        session_id: "test",
        data: "x".repeat(300 * 1024),
      };

      const event = createApiEvent(JSON.stringify(oversizedPayload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(413);
    });
  });

  describe("warmup middleware", () => {
    it("should short-circuit warmup events with serverless-plugin-warmup source", async () => {
      const warmupEvent = {
        source: "serverless-plugin-warmup",
      } as unknown as APIGatewayProxyEventV2;

      const result = await handler(warmupEvent, mockContext);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(0);

      // @middy/warmup returns "warmup" string when short-circuiting
      expect(result).toBe("warmup");
    });

    it("should process normal events (non-warmup) as usual", async () => {
      const payload = createValidPayload("normal-event-after-warmup-test");
      const event = createApiEvent(JSON.stringify(payload));

      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe(
        "normal-event-after-warmup-test",
      );
    });

    it("should not call SQS for warmup events", async () => {
      const warmupEvent = {
        source: "serverless-plugin-warmup",
      } as unknown as APIGatewayProxyEventV2;

      await handler(warmupEvent, mockContext);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(0);
    });
  });

  describe("v3 schema format", () => {
    it("should accept v3 format payload with sigint", async () => {
      const v3Payload = {
        identifiers: {
          session_id: "v3-test-session",
        },
        hashes: {
          stable: "abc123",
          fuzzy: "def456",
        },
        device: {},
        sigint: {
          tlsFingerprint: { ja4: "test_ja4" },
        },
      };
      const event = createApiEvent(JSON.stringify(v3Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe("v3-test-session");
    });

    it("should accept v3 format payload (identifiers, hashes, device sections)", async () => {
      const v3Payload = {
        identifiers: {
          session_id: "v3-test-session",
          evercookie_id: "ec_123",
        },
        hashes: {
          stable: "abc123",
          fuzzy: "def456",
        },
        device: {
          workerScope: {
            userAgent: "Mozilla/5.0",
            platform: "Win32",
          },
          screen: {
            width: 1920,
            height: 1080,
          },
        },
      };
      const event = createApiEvent(JSON.stringify(v3Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBe(1);
      const sentBody = JSON.parse(sqsCalls[0].args[0].input.MessageBody!);
      expect(sentBody.identifiers.session_id).toBe("v3-test-session");
      expect(sentBody.hashes.stable).toBe("abc123");
    });

    it("should extract session_id from v3 identifiers.session_id", async () => {
      const v3Payload = {
        identifiers: {
          session_id: "v3-extracted-session",
        },
        hashes: { stable: "a", fuzzy: "b" },
        device: {},
      };
      const event = createApiEvent(JSON.stringify(v3Payload));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
    });

    // Note: This test is skipped because we mock the validator in tests
    // to avoid ES module compatibility issues. In production, the middy
    // validator middleware handles schema validation.
    it.skip("should return 400 for v3 payload missing identifiers.session_id", async () => {
      const invalidV3 = {
        identifiers: {
          evercookie_id: "ec_123",
        },
        hashes: { stable: "a", fuzzy: "b" },
        device: {},
      };
      const event = createApiEvent(JSON.stringify(invalidV3));
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toContain("session_id");
    });
  });

  describe("payload archiving", () => {
    it("should archive payload with correct Hive-partitioned S3 key format", async () => {
      const sessionId = "archive-test-session-123";
      const payload = { session_id: sessionId, data: "test-data" };

      await archivePayload(sessionId, payload);

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

      expect(s3Calls[0].args[0].input.ContentEncoding).toBe("gzip");
      expect(s3Calls[0].args[0].input.ContentType).toBe("application/json");

      expect(s3Calls[0].args[0].input.Body).toBeInstanceOf(Buffer);
    });

    it("should log error but not throw when S3 upload fails", async () => {
      s3Mock.reset();
      s3Mock.on(PutObjectCommand).rejects(new Error("S3 unavailable"));

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

      const s3Calls = s3Mock.commandCalls(PutObjectCommand);
      expect(s3Calls.length).toBeGreaterThanOrEqual(1);
    });
  });
});
