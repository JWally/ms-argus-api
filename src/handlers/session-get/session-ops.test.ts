import { describe, it, expect, vi, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { gzipSync } from "zlib";
import {
  extractSessionId,
  lookupSession,
  fetchPayload,
  buildFallbackResponse,
  fetchVectorResults,
} from "./session-ops";
import { HttpError } from "../../helpers/http-error";
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";

const dynamoMock = mockClient(DynamoDBClient);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

function createEvent(
  method: string,
  sessionId?: string,
): APIGatewayProxyEventV2 {
  return {
    version: "2.0",
    routeKey: "GET /v1/session/{session_id}",
    rawPath: `/v1/session/${sessionId || ""}`,
    rawQueryString: "",
    headers: {},
    requestContext: {
      http: {
        method,
        path: "",
        protocol: "HTTP/1.1",
        sourceIp: "1.1.1.1",
        userAgent: "test",
      },
      accountId: "123",
      apiId: "test",
      domainName: "test",
      domainPrefix: "test",
      requestId: "test",
      routeKey: "GET /v1/session/{session_id}",
      stage: "test",
      time: "",
      timeEpoch: 0,
    },
    pathParameters: sessionId ? { session_id: sessionId } : undefined,
    isBase64Encoded: false,
  } as APIGatewayProxyEventV2;
}

describe("extractSessionId", () => {
  it("should throw preflight error for OPTIONS", () => {
    const event = createEvent("OPTIONS");
    try {
      extractSessionId(event, mockMetrics as any);
      expect.unreachable();
    } catch (e: any) {
      expect(e.preflight).toBe(true);
    }
  });

  it("should throw 405 for non-GET methods", () => {
    const event = createEvent("POST");
    expect(() => extractSessionId(event, mockMetrics as any)).toThrow(
      HttpError,
    );
    try {
      extractSessionId(event, mockMetrics as any);
    } catch (e) {
      expect((e as HttpError).statusCode).toBe(405);
    }
  });

  it("should throw 400 for missing session_id", () => {
    const event = createEvent("GET");
    expect(() => extractSessionId(event, mockMetrics as any)).toThrow(
      HttpError,
    );
  });

  it("should throw 400 for invalid session_id format", () => {
    const event = createEvent("GET", "a".repeat(129)); // too long
    expect(() => extractSessionId(event, mockMetrics as any)).toThrow(
      HttpError,
    );
  });

  it("should throw 400 for session_id with special chars", () => {
    const event = createEvent("GET", "session/../../etc");
    expect(() => extractSessionId(event, mockMetrics as any)).toThrow(
      HttpError,
    );
  });

  it("should return valid session_id", () => {
    const event = createEvent("GET", "session-abc-123");
    const id = extractSessionId(event, mockMetrics as any);
    expect(id).toBe("session-abc-123");
  });
});

describe("lookupSession", () => {
  const mockCacheService = {
    checkSessionCache: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return cached session", async () => {
    const session = { device_id: "dev_001", status: "complete" };
    mockCacheService.checkSessionCache.mockResolvedValue(session);

    const result = await lookupSession("session-123", {
      cacheService: mockCacheService as any,
      logger: mockLogger as any,
      metrics: mockMetrics as any,
    });

    expect(result).toEqual(session);
  });

  it("should throw 404 when session not found", async () => {
    mockCacheService.checkSessionCache.mockResolvedValue(null);

    await expect(
      lookupSession("session-123", {
        cacheService: mockCacheService as any,
        logger: mockLogger as any,
        metrics: mockMetrics as any,
      }),
    ).rejects.toThrow(HttpError);
  });

  it("should throw 503 on service error", async () => {
    mockCacheService.checkSessionCache.mockRejectedValue(
      new Error("DynamoDB error"),
    );

    await expect(
      lookupSession("session-123", {
        cacheService: mockCacheService as any,
        logger: mockLogger as any,
        metrics: mockMetrics as any,
      }),
    ).rejects.toThrow(HttpError);
  });

  it("should re-throw HttpErrors directly", async () => {
    mockCacheService.checkSessionCache.mockRejectedValue(
      new HttpError(404, "Session not found"),
    );

    try {
      await lookupSession("session-123", {
        cacheService: mockCacheService as any,
        logger: mockLogger as any,
        metrics: mockMetrics as any,
      });
      expect.unreachable();
    } catch (e) {
      expect((e as HttpError).statusCode).toBe(404);
    }
  });
});

describe("fetchPayload", () => {
  beforeEach(() => {
    dynamoMock.reset();
    vi.clearAllMocks();
  });

  const deps = {
    dynamodb: new DynamoDBClient({}),
    payloadTable: "test-payload-table",
    logger: mockLogger as any,
    metrics: mockMetrics as any,
  };

  it("should return undefined when item not found", async () => {
    dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
    const result = await fetchPayload("session-123", deps);
    expect(result).toBeUndefined();
  });

  it("should return undefined when payload_gzip_b64 is missing", async () => {
    dynamoMock.on(GetItemCommand).resolves({
      Item: { session_id: { S: "session-123" } },
    });
    const result = await fetchPayload("session-123", deps);
    expect(result).toBeUndefined();
  });

  it("should decompress and return valid payload", async () => {
    const payload = {
      identifiers: { session_id: "session-123", device_id: "dev_001" },
      analysis: {
        status: "complete",
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: 0.3,
        flags: [],
        evidence_codes: ["STABLE_HASH_MATCH"],
      },
      hashes: { stable: "hash-abc", fuzzy: "fuzzy-def" },
      device: {},
    };
    const gzipped = gzipSync(Buffer.from(JSON.stringify(payload)));
    const b64 = gzipped.toString("base64");

    dynamoMock.on(GetItemCommand).resolves({
      Item: {
        session_id: { S: "session-123" },
        payload_gzip_b64: { S: b64 },
      },
    });

    const result = await fetchPayload("session-123", deps);
    expect(result).toBeDefined();
    expect(result!.identifiers.device_id).toBe("dev_001");
  });

  it("should return undefined on error", async () => {
    dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB error"));
    const result = await fetchPayload("session-123", deps);
    expect(result).toBeUndefined();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SessionPayloadFetchError",
      expect.any(String),
      1,
    );
  });
});

describe("buildFallbackResponse", () => {
  it("should return degraded response with cached data", () => {
    const session = {
      device_id: "dev_001",
      status: "complete",
      confidence: 0.9,
      match_tier: 1,
      risk_score: 0.2,
      flags: [],
      evidence_codes: ["STABLE_HASH_MATCH"],
    };

    const result = buildFallbackResponse(
      session as any,
      "session-123",
      mockMetrics as any,
    );

    const r = result as APIGatewayProxyStructuredResultV2;
    expect(r.statusCode).toBe(200);
    expect(r.headers!["X-Argus-Degraded"]).toBe("true");
    const body = JSON.parse(r.body as string);
    expect(body.identifiers.device_id).toBe("dev_001");
    expect(body.analysis.confidence).toBe(0.9);
  });

  it("should use defaults for missing fields", () => {
    const session = { status: "complete" };

    const result = buildFallbackResponse(
      session as any,
      "session-123",
      mockMetrics as any,
    );

    const r = result as APIGatewayProxyStructuredResultV2;
    const body = JSON.parse(r.body as string);
    expect(body.identifiers.device_id).toBe("unknown");
    expect(body.analysis.confidence).toBe(0);
    expect(body.analysis.match_tier).toBe(-1);
    expect(body.analysis.risk_score).toBe(0);
  });
});

describe("fetchVectorResults", () => {
  beforeEach(() => {
    dynamoMock.reset();
    vi.clearAllMocks();
  });

  const deps = {
    dynamodb: new DynamoDBClient({}),
    vectorResultsTable: "test-vector-results",
    logger: mockLogger as any,
    metrics: mockMetrics as any,
  };

  it("should return undefined when no item found", async () => {
    dynamoMock.on(GetItemCommand).resolves({ Item: undefined });
    const result = await fetchVectorResults("session-123", deps);
    expect(result).toBeUndefined();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "VectorResultsNotFound",
      expect.any(String),
      1,
    );
  });

  it("should return vector results when found", async () => {
    const item = marshall({
      session_id: "session-123",
      results: [{ id: "dev_001", score: 0.95 }],
      collection: "fingerprints_v2",
      result_count: 1,
      top_score: 0.95,
      created_at: 1704067200000,
    });

    dynamoMock.on(GetItemCommand).resolves({ Item: item });
    const result = await fetchVectorResults("session-123", deps);

    expect(result).toBeDefined();
    expect(result!.session_id).toBe("session-123");
    expect(result!.results).toHaveLength(1);
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "VectorResultsFound",
      expect.any(String),
      1,
    );
  });

  it("should return undefined on error", async () => {
    dynamoMock.on(GetItemCommand).rejects(new Error("DynamoDB error"));
    const result = await fetchVectorResults("session-123", deps);
    expect(result).toBeUndefined();
    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "VectorResultsFetchError",
      expect.any(String),
      1,
    );
  });
});
