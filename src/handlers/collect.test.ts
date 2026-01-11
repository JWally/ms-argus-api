// src/handlers/collect.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";

// Mock validator module before importing handler (avoids ES module issue)
vi.mock("@middy/validator", () => ({
  default: () => ({
    before: vi.fn(),
    after: vi.fn(),
    onError: vi.fn(),
  }),
}));

vi.mock("@middy/validator/transpile", () => ({
  transpileSchema: vi.fn((schema: unknown) => schema),
}));

// Mock AWS SDK
const snsMock = mockClient(SNSClient);

// Mock environment variables before importing handler
vi.stubEnv(
  "FINGERPRINT_TOPIC_ARN",
  "arn:aws:sns:us-east-1:123456789:test-topic",
);
vi.stubEnv("POWERTOOLS_SERVICE_NAME", "argus-test");

// Import after mocking
import { lambdaHandler, logger, metrics } from "./collect";

// Suppress logger output during tests
vi.spyOn(logger, "info").mockImplementation(() => logger);
vi.spyOn(logger, "error").mockImplementation(() => logger);
vi.spyOn(metrics, "addMetric").mockImplementation(() => {});

// Helper to parse body for tests (simulates middleware)
function withParsedBody(event: APIGatewayProxyEventV2): APIGatewayProxyEventV2 {
  return {
    ...event,
    body: JSON.parse(event.body as string) as unknown as string,
  };
}

describe("collect handler", () => {
  beforeEach(() => {
    snsMock.reset();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createEvent = (
    overrides: Partial<APIGatewayProxyEventV2> = {},
  ): APIGatewayProxyEventV2 => ({
    version: "2.0",
    routeKey: "POST /collect",
    rawPath: "/collect",
    rawQueryString: "",
    headers: {
      "content-type": "application/json",
      "user-agent": "Mozilla/5.0 Test",
      accept: "application/json",
      "accept-language": "en-US",
      "accept-encoding": "gzip",
    },
    requestContext: {
      accountId: "123456789",
      apiId: "test-api",
      domainName: "test.execute-api.us-east-1.amazonaws.com",
      domainPrefix: "test",
      http: {
        method: "POST",
        path: "/collect",
        protocol: "HTTP/1.1",
        sourceIp: "192.168.1.1",
        userAgent: "Mozilla/5.0 Test",
      },
      requestId: "test-request-id",
      routeKey: "POST /collect",
      stage: "$default",
      time: "01/Jan/2025:00:00:00 +0000",
      timeEpoch: 1704067200000,
    },
    body: JSON.stringify({
      session_id: "test-session-123",
      js_fingerprint: {
        canvas: "abc123",
        webgl: "def456",
        screen: { width: 1920, height: 1080 },
      },
      tcp_blob: "encrypted-tcp-data",
      tls_blob: "encrypted-tls-data",
    }),
    isBase64Encoded: false,
    ...overrides,
  });

  describe("health check", () => {
    it("should return 200 for GET /health", async () => {
      const event = createEvent({
        rawPath: "/health",
        requestContext: {
          ...createEvent().requestContext,
          http: {
            method: "GET",
            path: "/health",
            protocol: "HTTP/1.1",
            sourceIp: "192.168.1.1",
            userAgent: "test",
          },
        },
      });

      const result = (await lambdaHandler(
        event,
      )) as APIGatewayProxyStructuredResultV2;

      expect(result.statusCode).toBe(200);
      expect(JSON.parse(result.body as string)).toEqual({
        status: "ok",
        service: "ms-argus-api",
      });
    });
  });

  describe("fingerprint collection", () => {
    it("should publish fingerprint to SNS and return success", async () => {
      snsMock.on(PublishCommand).resolves({ MessageId: "test-message-id" });

      const event = withParsedBody(createEvent());
      const result = (await lambdaHandler(
        event,
      )) as APIGatewayProxyStructuredResultV2;

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body as string);
      expect(body.status).toBe("ok");
      expect(body.session_id).toBe("test-session-123");

      // Verify SNS was called
      const snsCalls = snsMock.commandCalls(PublishCommand);
      expect(snsCalls).toHaveLength(1);

      const publishInput = snsCalls[0].args[0].input;
      expect(publishInput.TopicArn).toBe(
        "arn:aws:sns:us-east-1:123456789:test-topic",
      );

      const message = JSON.parse(publishInput.Message!.trim());
      expect(message.session_id).toBe("test-session-123");
      expect(message.ipAddress).toBe("192.168.1.1");
      expect(message.tcp_blob).toBe("encrypted-tcp-data");
      expect(message.tls_blob).toBe("encrypted-tls-data");
      expect(message["js.canvas"]).toBe("abc123");
      expect(message["js.webgl"]).toBe("def456");
      expect(message["js.screen.width"]).toBe(1920);
    });

    it("should handle fingerprint without optional blobs", async () => {
      snsMock.on(PublishCommand).resolves({ MessageId: "test-message-id" });

      const event = createEvent();
      event.body = { session_id: "test-session-456" } as unknown as string;

      const result = (await lambdaHandler(
        event,
      )) as APIGatewayProxyStructuredResultV2;

      expect(result.statusCode).toBe(200);

      const snsCalls = snsMock.commandCalls(PublishCommand);
      const message = JSON.parse(snsCalls[0].args[0].input.Message!.trim());
      expect(message.session_id).toBe("test-session-456");
      expect(message.tcp_blob).toBeNull();
      expect(message.tls_blob).toBeNull();
    });

    it("should include request headers in payload", async () => {
      snsMock.on(PublishCommand).resolves({ MessageId: "test-message-id" });

      const event = withParsedBody(createEvent());
      event.headers = {
        ...event.headers,
        "user-agent": "CustomBrowser/1.0",
        referer: "https://example.com",
        origin: "https://example.com",
        "x-forwarded-for": "10.0.0.1, 192.168.1.1",
      };

      await lambdaHandler(event);

      const snsCalls = snsMock.commandCalls(PublishCommand);
      const message = JSON.parse(snsCalls[0].args[0].input.Message!.trim());
      expect(message["headers.user_agent"]).toBe("CustomBrowser/1.0");
      expect(message["headers.referer"]).toBe("https://example.com");
      expect(message["headers.origin"]).toBe("https://example.com");
      expect(message["headers.x_forwarded_for"]).toBe("10.0.0.1, 192.168.1.1");
    });

    it("should include date partitioning info", async () => {
      snsMock.on(PublishCommand).resolves({ MessageId: "test-message-id" });

      const event = withParsedBody(createEvent());
      await lambdaHandler(event);

      const snsCalls = snsMock.commandCalls(PublishCommand);
      const message = JSON.parse(snsCalls[0].args[0].input.Message!.trim());
      expect(message["DATE_INFO.year"]).toBeDefined();
      expect(message["DATE_INFO.month"]).toBeDefined();
      expect(message["DATE_INFO.day"]).toBeDefined();
      expect(message["meta.timestamp"]).toBeDefined();
      expect(message["meta.argus_version"]).toBe("1.0.0");
    });

    it("should record success metric", async () => {
      snsMock.on(PublishCommand).resolves({ MessageId: "test-message-id" });

      const event = withParsedBody(createEvent());
      await lambdaHandler(event);

      expect(metrics.addMetric).toHaveBeenCalledWith(
        "FingerprintCollected",
        "Count",
        1,
      );
    });
  });

  describe("error handling", () => {
    it("should throw error when FINGERPRINT_TOPIC_ARN is not set", async () => {
      vi.stubEnv("FINGERPRINT_TOPIC_ARN", "");

      const event = withParsedBody(createEvent());
      await expect(lambdaHandler(event)).rejects.toThrow();

      // Restore
      vi.stubEnv(
        "FINGERPRINT_TOPIC_ARN",
        "arn:aws:sns:us-east-1:123456789:test-topic",
      );
    });

    it("should throw error when IP address is missing", async () => {
      const event = withParsedBody(createEvent());
      (event.requestContext.http as { sourceIp?: string }).sourceIp = undefined;

      await expect(lambdaHandler(event)).rejects.toThrow();
    });

    it("should throw error when headers are missing", async () => {
      const event = withParsedBody(createEvent());
      (event as { headers?: unknown }).headers = undefined;

      await expect(lambdaHandler(event)).rejects.toThrow();
    });

    it("should throw error when body is missing", async () => {
      const event = createEvent();
      (event as { body?: unknown }).body = undefined;

      await expect(lambdaHandler(event)).rejects.toThrow();
    });

    it("should handle SNS publish failure", async () => {
      snsMock.on(PublishCommand).rejects(new Error("SNS publish failed"));

      const event = withParsedBody(createEvent());
      await expect(lambdaHandler(event)).rejects.toThrow();
      expect(metrics.addMetric).toHaveBeenCalledWith(
        "FingerprintError",
        "Count",
        1,
      );
    });
  });
});
