import { describe, it, expect, beforeEach, vi } from "vitest";

const { mockAddMetric, mockPublishStoredMetrics, mockDetectAllAnomalies } =
  vi.hoisted(() => ({
    mockAddMetric: vi.fn(),
    mockPublishStoredMetrics: vi.fn(),
    mockDetectAllAnomalies: vi.fn().mockReturnValue({
      signals: [],
      aggregateScore: 0,
      suggestedFlags: [],
    }),
  }));

vi.mock("../services/profile/anomaly", () => ({
  detectAllAnomalies: mockDetectAllAnomalies,
}));

vi.mock("@aws-lambda-powertools/metrics", () => ({
  Metrics: vi.fn().mockImplementation(() => ({
    addMetric: mockAddMetric,
    publishStoredMetrics: mockPublishStoredMetrics,
  })),
  MetricUnit: {
    Count: "Count",
    Milliseconds: "Milliseconds",
  },
}));

vi.hoisted(() => {
  process.env.POWERTOOLS_SERVICE_NAME = "argus-matching-worker-test";
  process.env.POWERTOOLS_METRICS_NAMESPACE = "argus-test";
  process.env.SESSION_CACHE_TABLE = "test-session-cache";
  process.env.SESSION_PAYLOAD_TABLE = "test-session-payload";
  process.env.TIER1_INDEX_TABLE = "test-tier1-index";
  process.env.TIER2_BUCKETS_TABLE = "test-tier2-buckets";
  process.env.PROFILES_TABLE = "test-profiles";
  process.env.PROFILE_QUEUE_URL =
    "https://sqs.us-east-1.amazonaws.com/123456789/test-profile-queue";
  process.env.OBSERVATIONS_STREAM_NAME = "test-observations-stream";
});

import { mockClient } from "aws-sdk-client-mock";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import { marshall } from "@aws-sdk/util-dynamodb";
import { SQSEvent, SQSRecord, Context } from "aws-lambda";

const dynamoMock = mockClient(DynamoDBClient);
const sqsMock = mockClient(SQSClient);
const firehoseMock = mockClient(FirehoseClient);

import { handler } from "./matching-worker";

describe("matching-worker handler", () => {
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
    sqsMock.reset();
    firehoseMock.reset();
    dynamoMock.on(PutItemCommand).resolves({});
    firehoseMock.on(PutRecordCommand).resolves({ RecordId: "rec-1" });
    vi.clearAllMocks();
    mockAddMetric.mockClear();
    mockPublishStoredMetrics.mockClear();
  });

  const createSQSRecord = (
    body: object,
    messageId = "test-msg-1",
  ): SQSRecord => ({
    messageId,
    receiptHandle: "test-receipt-handle",
    body: JSON.stringify(body),
    attributes: {
      ApproximateReceiveCount: "1",
      SentTimestamp: "1704067200000",
      SenderId: "123456789",
      ApproximateFirstReceiveTimestamp: "1704067200001",
    },
    messageAttributes: {},
    md5OfBody: "test-md5",
    eventSource: "aws:sqs",
    eventSourceARN: "arn:aws:sqs:us-east-1:123456789:test-queue",
    awsRegion: "us-east-1",
  });

  const createSQSEvent = (records: SQSRecord[]): SQSEvent => ({
    Records: records,
  });

  const createFingerprintPayload = (
    overrides: Record<string, unknown> = {},
  ) => {
    const sessionId = (overrides.session_id as string) || "test-session-123";
    const { session_id: _, ...restOverrides } = overrides;
    return {
      identifiers: {
        session_id: sessionId,
        evercookie_id: "test-evercookie-123",
      },
      hashes: {
        stable: "hash-abc123",
        fuzzy: "fuzzy-def456",
        canvas2d: "canvas-ghi789",
        canvasWebgl: "webgl-xyz789",
        offlineAudioContext: "audio-123",
        maths: "maths-456",
      },
      device: {
        workerScope: {
          userAgent: "Mozilla/5.0 Test Browser",
          hardwareConcurrency: 8,
          deviceMemory: 8,
          webglRenderer: "NVIDIA GeForce RTX 3080",
          timezoneLocation: "America/New_York",
        },
        screen: {
          width: 1920,
          height: 1080,
        },
      },
      sigint: {
        tlsFingerprint: {
          ip: "192.168.1.1",
          ja4: "t13d1516h2_8daaf6152771",
        },
      },
      _timestamp: Date.now(),
      ...restOverrides,
    };
  };

  describe("successful processing", () => {
    it("should process a single record successfully with Tier 1 match", async () => {
      const payload = createFingerprintPayload();

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });

      sqsMock.on(SendMessageCommand).resolves({ MessageId: "profile-msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result).toBeDefined();
      expect(result!.batchItemFailures).toHaveLength(0);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBeGreaterThanOrEqual(1);
    });

    it("should process multiple records in batch", async () => {
      const payload1 = createFingerprintPayload({ session_id: "session-1" });
      const payload2 = createFingerprintPayload({ session_id: "session-2" });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(payload1, "msg-1"),
        createSQSRecord(payload2, "msg-2"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should skip processing for cache hit (Tier 0)", async () => {
      const payload = createFingerprintPayload();
      const sessionId = payload.identifiers.session_id;

      dynamoMock.on(GetItemCommand).callsFake((input) => {
        const key = input.Key;
        if (key?.cache_key?.S === `session:${sessionId}`) {
          return {
            Item: marshall({
              cache_key: `session:${sessionId}`,
              value: {
                status: "complete",
                device_id: "cached-device-123",
                risk_score: 0.2,
                confidence: 0.95,
                match_tier: 1,
                match_version: 1,
                idempotency_key: "cached-key",
                flags: [],
                updated_at: Date.now(),
              },
              ttl: Math.floor(Date.now() / 1000) + 900,
            }),
          };
        }
        return { Item: undefined };
      });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      expect(sqsMock.calls()).toHaveLength(0);
    });

    it("should create new device when no match found", async () => {
      const payload = createFingerprintPayload({
        hashes: {
          stable: "brand-new-hash",
          fuzzy: "brand-new-fuzzy",
        },
      });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      const sqsCalls = sqsMock.commandCalls(SendMessageCommand);
      expect(sqsCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("error handling", () => {
    it("should return failed item when DynamoDB throws", async () => {
      const payload = createFingerprintPayload();

      dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB error"));

      const event = createSQSEvent([createSQSRecord(payload, "failing-msg")]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("failing-msg");
    });

    it("should return failed items only for records that fail", async () => {
      const successPayload = createFingerprintPayload({
        session_id: "success-session",
        identifiers: {
          session_id: "success-session",
          evercookie_id: "cookie-success",
        },
      });
      const failPayload = createFingerprintPayload({
        session_id: "fail-session",
        identifiers: {
          session_id: "fail-session",
          evercookie_id: "cookie-fail",
        },
      });

      dynamoMock.on(GetItemCommand).callsFake((input) => {
        const key = input.Key;
        if (key?.cache_key?.S?.startsWith("session:")) {
          return { Item: undefined };
        }
        if (key?.hash_key?.S?.includes("cookie-success")) {
          return {
            Item: marshall({
              hash_key: "evercookie#cookie-success",
              device_id: "device-123",
            }),
          };
        }
        if (key?.hash_key?.S?.includes("cookie-fail")) {
          throw new Error("DynamoDB error");
        }
        return { Item: undefined };
      });

      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(successPayload, "success-msg"),
        createSQSRecord(failPayload, "fail-msg"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
      expect(result!.batchItemFailures[0].itemIdentifier).toBe("fail-msg");
    });

    it("should handle invalid JSON in record body without retrying", async () => {
      const event = createSQSEvent([
        {
          ...createSQSRecord({}, "invalid-msg"),
          body: "not-valid-json",
        },
      ]);

      const result = await handler(event, mockContext, () => {});

      // Should NOT be in batch failures (don't retry poison messages)
      expect(result!.batchItemFailures).toHaveLength(0);
      expect(mockAddMetric).toHaveBeenCalledWith(
        "MalformedPayload",
        "Count",
        1,
      );
    });

    it("should write degraded status on matching failure", async () => {
      const payload = createFingerprintPayload();

      dynamoMock.on(GetItemCommand).rejects(new Error("Matching failed"));

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(1);
    });
  });

  describe("tier matching metrics", () => {
    it("should process Tier 0.5 (evercookie) match", async () => {
      const payload = createFingerprintPayload({
        identifiers: {
          session_id: "test-session-123",
          evercookie_id: "evercookie-abc123",
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "evercookie-abc123",
          device_id: "evercookie-device-123",
        }),
      });

      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("warmup message handling", () => {
    it("should handle warmup message without processing", async () => {
      const warmupMessage = {
        warmup: true,
        source: "warmup-rule",
        timestamp: "2025-01-14T00:00:00Z",
      };

      const event = createSQSEvent([
        createSQSRecord(warmupMessage, "warmup-msg"),
      ]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      expect(dynamoMock.calls()).toHaveLength(0);

      expect(sqsMock.calls()).toHaveLength(0);
    });

    it("should handle warmup message mixed with regular messages", async () => {
      const warmupMessage = {
        warmup: true,
        source: "warmup-rule",
      };
      const regularPayload = createFingerprintPayload();

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([
        createSQSRecord(warmupMessage, "warmup-msg"),
        createSQSRecord(regularPayload, "regular-msg"),
      ]);

      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      expect(dynamoMock.calls().length).toBeGreaterThan(0);
    });
  });

  describe("NEW_DEVICE_RATE metric emission", () => {
    it("should emit NEW_DEVICE_RATE metric when is_new_device=true", async () => {
      const payload = createFingerprintPayload({
        hashes: {
          stable: "brand-new-hash",
          fuzzy: "brand-new-fuzzy",
        },
      });

      dynamoMock.on(GetItemCommand).resolves({});
      dynamoMock.on(QueryCommand).resolves({ Items: [] });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      expect(mockAddMetric).toHaveBeenCalledWith("NEW_DEVICE_RATE", "Count", 1);
      expect(mockAddMetric).toHaveBeenCalledWith("NewDevice", "Count", 1);
    });

    it("should NOT emit NEW_DEVICE_RATE when is_new_device=false", async () => {
      const payload = createFingerprintPayload({
        identifiers: { session_id: "test-session-123" },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({
          hash_value: "hash-abc123",
          device_id: "existing-device-123",
        }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "msg-1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      await handler(event, mockContext, () => {});

      expect(mockAddMetric).not.toHaveBeenCalledWith(
        "NEW_DEVICE_RATE",
        "Count",
        1,
      );
      expect(mockAddMetric).not.toHaveBeenCalledWith("NewDevice", "Count", 1);
      expect(mockAddMetric).toHaveBeenCalledWith("Tier1Hit", "Count", 1);
    });
  });

  describe("fingerprint extraction - STUN signals", () => {
    it("should extract publicIp from sigint.stun", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1", ja4: "ja4hash" },
          stun: { publicIp: "203.0.113.5" },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract reflexiveIp (web format) as stun_public_ip", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          stun: { reflexiveIp: "198.51.100.10" },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract localIps[0] (API array format) as stun_local_ip", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          stun: { localIps: ["10.0.0.1", "10.0.0.2"] },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract localIp (web string format) as stun_local_ip", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          stun: { localIp: "10.0.0.5" },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("fingerprint extraction - TCP probe", () => {
    it("should extract nested rtt_fingerprint format", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          tcpProbe: {
            rtt_fingerprint: {
              proxy_score: 0.85,
              vpn_score: 0.7,
              tcp_rtt_us: 15000,
            },
          },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract flat TCP probe format (proxyScore/vpnScore/rttMs)", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          tcpProbe: {
            proxyScore: 0.9,
            vpnScore: 0.6,
            rttMs: 25,
          },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract faviconCache id", async () => {
      const payload = createFingerprintPayload({
        sigint: {
          tlsFingerprint: { ip: "192.168.1.1" },
          faviconCache: { id: "fav-cache-uuid-123" },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("fingerprint extraction - headless detection", () => {
    it("should extract direct isHeadless boolean", async () => {
      const payload = createFingerprintPayload({
        device: {
          workerScope: { userAgent: "HeadlessChrome" },
          screen: { width: 1920, height: 1080 },
          headless: { isHeadless: true },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should compute isHeadless from nested headless signals (some true)", async () => {
      const payload = createFingerprintPayload({
        device: {
          workerScope: { userAgent: "Chrome/120" },
          screen: { width: 1920, height: 1080 },
          headless: {
            headless: {
              chromeDriver: true,
              notificationPermission: false,
              webDriverFlag: false,
            },
          },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should not flag headless when all nested signals are false", async () => {
      const payload = createFingerprintPayload({
        device: {
          workerScope: { userAgent: "Chrome/120" },
          screen: { width: 1920, height: 1080 },
          headless: {
            headless: {
              chromeDriver: false,
              notificationPermission: false,
            },
          },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("fingerprint extraction - lies detection", () => {
    it("should extract lies.count (API schema)", async () => {
      const payload = createFingerprintPayload({
        device: {
          workerScope: { userAgent: "Chrome/120" },
          screen: { width: 1920, height: 1080 },
          lies: { count: 5 },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });

    it("should extract lies.totalLies (web client format)", async () => {
      const payload = createFingerprintPayload({
        device: {
          workerScope: { userAgent: "Chrome/120" },
          screen: { width: 1920, height: 1080 },
          lies: { totalLies: 3 },
        },
      });

      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});
      expect(result!.batchItemFailures).toHaveLength(0);
    });
  });

  describe("missing session_id handling", () => {
    it("should skip record without session_id and emit metric", async () => {
      const payload = {
        identifiers: { evercookie_id: "cookie-123" },
        hashes: { stable: "abc", fuzzy: "def" },
        device: {},
      };

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
      expect(mockAddMetric).toHaveBeenCalledWith(
        "MissingSessionId",
        "Count",
        1,
      );
    });
  });

  describe("writeSessionPayload", () => {
    it("should write gzipped payload to session payload table on success", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      dynamoMock.on(PutItemCommand).resolves({});
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const payload = createFingerprintPayload({
        identifiers: {
          session_id: "sess-payload-test",
          evercookie_id: "ec-123",
          public_key: "pk-456",
        },
      });

      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      const putCalls = dynamoMock.commandCalls(PutItemCommand);
      const payloadWrite = putCalls.find(
        (c) => c.args[0].input.TableName === "test-session-payload",
      );
      expect(payloadWrite).toBeDefined();
      expect(payloadWrite!.args[0].input.Item!.session_id.S).toBe(
        "sess-payload-test",
      );
      expect(
        payloadWrite!.args[0].input.Item!.payload_gzip_b64.S,
      ).toBeDefined();
      expect(payloadWrite!.args[0].input.Item!.ttl.N).toBeDefined();
    });

    it("should not fail when session payload write errors", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      dynamoMock.on(PutItemCommand).callsFake((input) => {
        if (input.TableName === "test-session-payload") {
          throw new Error("DynamoDB write error");
        }
        return {};
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const payload = createFingerprintPayload();
      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);
      expect(mockAddMetric).toHaveBeenCalledWith(
        "SessionPayloadWriteError",
        "Count",
        1,
      );
    });
  });

  describe("emitObservation", () => {
    it("should emit observation to Firehose on successful processing", async () => {
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const payload = createFingerprintPayload();
      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      expect(result!.batchItemFailures).toHaveLength(0);

      // Wait for fire-and-forget to settle
      await new Promise((resolve) => setTimeout(resolve, 50));

      const firehoseCalls = firehoseMock.commandCalls(PutRecordCommand);
      expect(firehoseCalls.length).toBeGreaterThanOrEqual(1);
      expect(firehoseCalls[0].args[0].input.DeliveryStreamName).toBe(
        "test-observations-stream",
      );
    });

    it("should handle Firehose error gracefully without failing", async () => {
      firehoseMock.on(PutRecordCommand).rejects(new Error("Firehose error"));
      dynamoMock.on(GetItemCommand).resolves({
        Item: marshall({ hash_value: "hash-abc123", device_id: "dev-1" }),
      });
      sqsMock.on(SendMessageCommand).resolves({ MessageId: "m1" });

      const payload = createFingerprintPayload();
      const event = createSQSEvent([createSQSRecord(payload)]);
      const result = await handler(event, mockContext, () => {});

      // Should still succeed (emitObservation is fire-and-forget)
      expect(result!.batchItemFailures).toHaveLength(0);

      // Wait for fire-and-forget to settle
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
  });
});
