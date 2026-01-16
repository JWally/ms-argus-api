// src/handlers/ingestion-tenant-guard.test.ts
// AR-124: Tests for tenant isolation guard - throws in production when missing API key config
/* eslint-disable @typescript-eslint/no-explicit-any */

import {
  describe,
  it,
  expect,
  beforeEach,
  vi,
  beforeAll,
  afterAll,
} from "vitest";

// Store original env
const originalEnv = { ...process.env };

describe("AR-124: Tenant isolation guard in production", () => {
  beforeAll(() => {
    // Set production stage BEFORE importing handler
    process.env.STAGE = "prod";
    process.env.POWERTOOLS_SERVICE_NAME = "argus-ingestion-test";
    process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
    process.env.SQS_QUEUE_URL =
      "https://sqs.us-east-1.amazonaws.com/123456789/test-queue";
    // No API_KEYS env var - this triggers the guard
  });

  afterAll(() => {
    // Restore original env
    process.env = originalEnv;
    vi.resetModules();
  });

  beforeEach(() => {
    vi.resetModules();
  });

  it("should throw 500 when STAGE=prod and no tenant identification", async () => {
    // Dynamic import after env is set
    const { mockClient } = await import("aws-sdk-client-mock");
    const { SQSClient, SendMessageCommand } =
      await import("@aws-sdk/client-sqs");
    const sqsMock = mockClient(SQSClient);
    sqsMock.on(SendMessageCommand).resolves({});

    const { handler } = await import("./ingestion");

    const event = {
      version: "2.0",
      routeKey: "POST /v1/collect",
      rawPath: "/v1/collect",
      rawQueryString: "",
      headers: {
        "content-type": "application/json",
        // No x-tenant-id header
        // No x-api-key header
      },
      requestContext: {
        accountId: "123456789",
        apiId: "test-api",
        domainName: "api.example.com",
        domainPrefix: "api",
        http: {
          method: "POST",
          path: "/v1/collect",
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
      body: JSON.stringify({
        session_id: "test-session-123",
        fingerprint: { hashes: { stable: "abc" } },
      }),
      isBase64Encoded: false,
    };

    const mockContext = {
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

    const result = await handler(event as any, mockContext as any);
    const typedResult = result as { statusCode: number; body?: string };

    expect(typedResult.statusCode).toBe(500);
    const body = JSON.parse(typedResult.body ?? "{}");
    expect(body.error).toContain("Tenant configuration error");
    expect(body.error).toContain("contact support");
  });
});
