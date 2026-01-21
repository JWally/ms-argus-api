// src/handlers/session-get.test.ts
// AR-67: Tests for session retrieval endpoint
import { describe, it, expect, beforeEach, vi } from "vitest";

// Set environment variables BEFORE any module imports using vi.hoisted
vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-session-get-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SESSION_CACHE_TABLE = "test-session-cache";
  process.env.SESSION_PAYLOAD_TABLE = "test-session-payload"; // AR-XXX: Full payload storage
});

import { mockClient } from "aws-sdk-client-mock";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { gzipSync } from "zlib";
import {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  Context,
} from "aws-lambda";

// Mock AWS SDK clients
const dynamoMock = mockClient(DynamoDBClient);

// Import handler after mocking
import { handler } from "./session-get";

// Helper to cast result (handler always returns structured result)
const asResult = (result: unknown): APIGatewayProxyStructuredResultV2 =>
  result as APIGatewayProxyStructuredResultV2;

describe("session-get handler", () => {
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
    dynamoMock.reset();
    vi.clearAllMocks();
  });

  const createApiEvent = (
    sessionId: string | null,
    method = "GET",
    origin?: string,
  ): APIGatewayProxyEventV2 => ({
    version: "2.0",
    routeKey: "GET /v1/session/{session_id}",
    rawPath: sessionId ? `/v1/session/${sessionId}` : "/v1/session/",
    rawQueryString: "",
    headers: {
      "content-type": "application/json",
      ...(origin ? { origin } : {}),
    },
    requestContext: {
      accountId: "123456789",
      apiId: "test-api",
      domainName: "api.example.com",
      domainPrefix: "api",
      http: {
        method,
        path: sessionId ? `/v1/session/${sessionId}` : "/v1/session/",
        protocol: "HTTP/1.1",
        sourceIp: "127.0.0.1",
        userAgent: "test-agent",
      },
      requestId: "test-request",
      routeKey: "GET /v1/session/{session_id}",
      stage: "$default",
      time: "01/Jan/2025:00:00:00 +0000",
      timeEpoch: 1704067200000,
    },
    pathParameters: sessionId ? { session_id: sessionId } : undefined,
    isBase64Encoded: false,
  });

  const mockSessionCacheValue = {
    status: "complete",
    device_id: "device-abc123",
    confidence: 0.95,
    match_tier: 1,
    match_version: 1,
    idempotency_key: "idem-key-123",
    risk_score: 0.2,
    flags: ["returning_user"],
    evidence_codes: ["STABLE_HASH_MATCH"],
    updated_at: Date.now(),
  };

  // V3 format payload stored in session payload table
  const createMockV3Payload = (sessionId: string) => ({
    identifiers: {
      session_id: sessionId,
      device_id: "device-abc123",
      evercookie_id: "test-evercookie",
    },
    analysis: {
      status: "complete",
      confidence: 0.95,
      match_tier: 1,
      is_new_device: false,
      risk_score: 0.2,
      flags: ["returning_user"],
      evidence_codes: ["STABLE_HASH_MATCH"],
    },
    hashes: {
      stable: "hash-abc123",
      fuzzy: "fuzzy-def456",
    },
    device: {
      workerScope: {
        userAgent: "Test Browser",
      },
    },
    sigint: {
      tlsFingerprint: {
        ip: "192.168.1.1",
      },
    },
  });

  // Helper to create gzipped base64 payload
  const createGzippedPayload = (payload: object): string => {
    const json = JSON.stringify(payload);
    const gzipped = gzipSync(Buffer.from(json));
    return gzipped.toString("base64");
  };

  describe("successful retrieval", () => {
    it("should retrieve a session successfully", async () => {
      const sessionId = "test-session-123";
      const ttl = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const v3Payload = createMockV3Payload(sessionId);

      // Mock both DynamoDB calls: session cache and session payload
      dynamoMock.on(GetItemCommand).callsFake((input) => {
        const tableName = input.TableName;
        if (tableName === "test-session-cache") {
          return {
            Item: marshall({
              cache_key: `session:${sessionId}`,
              value: mockSessionCacheValue,
              confidence: mockSessionCacheValue.confidence,
              ttl,
            }),
          };
        } else if (tableName === "test-session-payload") {
          return {
            Item: marshall({
              session_id: sessionId,
              payload_gzip_b64: createGzippedPayload(v3Payload),
              ttl,
            }),
          };
        }
        return {};
      });

      const event = createApiEvent(sessionId, "GET", "https://example.com");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(200);
      expect(result.headers?.["Access-Control-Allow-Origin"]).toBe(
        "https://example.com",
      );

      const body = JSON.parse(result.body ?? "");
      // V3 format response structure
      // Identifiers section
      expect(body.identifiers.session_id).toBe(sessionId);
      expect(body.identifiers.device_id).toBe("device-abc123");
      // Analysis section
      expect(body.analysis.status).toBe("complete");
      expect(body.analysis.confidence).toBe(0.95);
      expect(body.analysis.match_tier).toBe(1);
      expect(body.analysis.risk_score).toBe(0.2);
      expect(body.analysis.flags).toEqual(["returning_user"]);
      expect(body.analysis.evidence_codes).toEqual(["STABLE_HASH_MATCH"]);
      // Hashes section (V3)
      expect(body.hashes.stable).toBe("hash-abc123");
      expect(body.hashes.fuzzy).toBe("fuzzy-def456");
      // Device section
      expect(body.device).toBeDefined();
      // Should NOT include internal fields
      expect(body.analysis.idempotency_key).toBeUndefined();
      expect(body.analysis.match_version).toBeUndefined();
    });

    it("should handle pending session status", async () => {
      const sessionId = "pending-session";
      const pendingValue = { ...mockSessionCacheValue, status: "pending" };
      const ttl = Math.floor(Date.now() / 1000) + 3600;

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: `session:${sessionId}`,
          value: pendingValue,
          confidence: pendingValue.confidence,
          ttl,
        }),
      });

      const event = createApiEvent(sessionId);
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body ?? "");
      // AR-185: v2 format - status is in analysis section
      expect(body.analysis.status).toBe("pending");
    });
  });

  describe("session not found", () => {
    it("should return 404 when session does not exist", async () => {
      dynamoMock.on(GetItemCommand).resolves({});

      const event = createApiEvent("nonexistent-session");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Session not found");
    });

    it("should return 404 when session is expired", async () => {
      const sessionId = "expired-session";
      const expiredTtl = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          cache_key: `session:${sessionId}`,
          value: mockSessionCacheValue,
          confidence: mockSessionCacheValue.confidence,
          ttl: expiredTtl,
        }),
      });

      const event = createApiEvent(sessionId);
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Session not found");
    });
  });

  describe("validation errors", () => {
    it("should return 400 when session_id is missing", async () => {
      const event = createApiEvent(null);
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Missing session_id parameter");
    });

    it("should return 400 for invalid session_id format (too long)", async () => {
      const longSessionId = "a".repeat(129);
      const event = createApiEvent(longSessionId);
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Invalid session_id format");
    });

    it("should return 400 for invalid session_id format (special chars)", async () => {
      const event = createApiEvent("session<script>alert(1)</script>");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Invalid session_id format");
    });

    it("should accept valid session_id with hyphens and underscores", async () => {
      const sessionId = "valid-session_123-abc";
      dynamoMock.on(GetItemCommand).resolves({});

      const event = createApiEvent(sessionId);
      const result = asResult(await handler(event, mockContext));

      // Should get to DynamoDB lookup (returns 404 for not found, not 400)
      expect(result.statusCode).toBe(404);
    });
  });

  describe("HTTP methods", () => {
    it("should return 405 for POST method", async () => {
      const event = createApiEvent("test-session", "POST");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(405);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Method not allowed");
    });

    it("should return 204 for OPTIONS (CORS preflight)", async () => {
      const event = createApiEvent(
        "test-session",
        "OPTIONS",
        "https://test.com",
      );
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(204);
      expect(result.headers?.["Access-Control-Allow-Origin"]).toBe(
        "https://test.com",
      );
    });
  });

  describe("error handling", () => {
    it("should return 503 when DynamoDB fails", async () => {
      dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB unavailable"));

      const event = createApiEvent("test-session");
      const result = asResult(await handler(event, mockContext));

      expect(result.statusCode).toBe(503);
      const body = JSON.parse(result.body ?? "");
      expect(body.error).toBe("Service temporarily unavailable");
    });
  });

  describe("CORS headers", () => {
    it("should include CORS headers when origin is provided", async () => {
      dynamoMock.on(GetItemCommand).resolves({});

      const event = createApiEvent(
        "test-session",
        "GET",
        "https://app.example.com",
      );
      const result = asResult(await handler(event, mockContext));

      expect(result.headers?.["Access-Control-Allow-Origin"]).toBe(
        "https://app.example.com",
      );
      expect(result.headers?.["Access-Control-Allow-Methods"]).toBe(
        "GET, OPTIONS",
      );
    });

    it("should not include CORS headers when origin is missing", async () => {
      dynamoMock.on(GetItemCommand).resolves({});

      const event = createApiEvent("test-session", "GET");
      const result = asResult(await handler(event, mockContext));

      expect(result.headers?.["Access-Control-Allow-Origin"]).toBeUndefined();
    });
  });
});
