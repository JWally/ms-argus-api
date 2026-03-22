import { describe, it, expect, vi, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { buildSessionResponseData, writeSessionPayload } from "./session";
import type { MatchResult } from "../../services/matching";

const dynamoMock = mockClient(DynamoDBClient);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

const baseMatchResult: MatchResult = {
  device_id: "dev_001",
  confidence: 0.95,
  match_tier: 1,
  is_new_device: false,
  risk_score: 0.3,
  flags: [],
  evidence_codes: ["STABLE_HASH_MATCH"],
};

const basePayload = {
  identifiers: {
    session_id: "session-123",
    evercookie_id: "ec-456",
    public_key: "pk-789",
  },
  hashes: { stable: "hash-abc", fuzzy: "fuzzy-def" },
  device: {},
  sigint: {},
};

describe("buildSessionResponseData", () => {
  it("should build basic response with identifiers and analysis", () => {
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: basePayload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect(result.identifiers).toEqual({
      session_id: "session-123",
      device_id: "dev_001",
      evercookie_id: "ec-456",
      public_key: "pk-789",
    });
    expect((result.analysis as any).status).toBe("complete");
    expect((result.analysis as any).confidence).toBe(0.95);
  });

  it("should omit optional identifiers when not present", () => {
    const payload = {
      ...basePayload,
      identifiers: { session_id: "session-123" },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: payload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect(result.identifiers).toEqual({
      session_id: "session-123",
      device_id: "dev_001",
    });
  });

  it("should include browser anomalies when lies detected", () => {
    const payload = {
      ...basePayload,
      device: {
        lies: { totalLies: 3, data: [{ category: "navigator" }] },
      },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: payload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect((result.analysis as any).anomalies).toBeDefined();
    expect((result.analysis as any).anomalies.lies.total).toBe(3);
  });

  it("should include headless detection when ratings > 0", () => {
    const payload = {
      ...basePayload,
      device: {
        headless: {
          likeHeadlessRating: 0.5,
          headlessRating: 0,
          stealthRating: 0,
          likeHeadless: true,
          headless: false,
          stealth: false,
        },
      },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: payload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect((result.analysis as any).anomalies.headless).toBeDefined();
  });

  it("should omit headless when all ratings are 0", () => {
    const payload = {
      ...basePayload,
      device: {
        headless: {
          likeHeadlessRating: 0,
          headlessRating: 0,
          stealthRating: 0,
        },
      },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: payload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect((result.analysis as any).anomalies).toBeUndefined();
  });

  it("should include captured errors when present", () => {
    const payload = {
      ...basePayload,
      device: {
        capturedErrors: { data: ["Error 1", "Error 2"] },
      },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: payload as any,
      matchResult: baseMatchResult,
      anomalies: [],
    });

    expect((result.analysis as any).anomalies.errors).toHaveLength(2);
  });

  it("should include suspicious anomalies when present", () => {
    const anomalies = [
      {
        type: "NETWORK",
        code: "NEW_ASN_FOR_DEVICE",
        severity: 0.3,
        evidence: { expected: "known", actual: "unknown" },
      },
    ];
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: basePayload as any,
      matchResult: baseMatchResult,
      anomalies: anomalies as any,
    });

    expect((result.analysis as any).suspicious).toHaveLength(1);
  });

  it("should include vector and fuzzy match details when present", () => {
    const matchWithDetails = {
      ...baseMatchResult,
      fuzzy_match_info: { distance: 5 },
      vector_match_details: { similarity_score: 0.92 },
      ip_history_context: { known_ip: true },
    };
    const result = buildSessionResponseData({
      sessionId: "session-123",
      rawPayload: basePayload as any,
      matchResult: matchWithDetails as any,
      anomalies: [],
    });

    expect((result.analysis as any).fuzzy_match_info).toBeDefined();
    expect((result.analysis as any).vector_match_details).toBeDefined();
    expect((result.analysis as any).ip_history_context).toBeDefined();
  });
});

describe("writeSessionPayload", () => {
  beforeEach(() => {
    dynamoMock.reset();
    dynamoMock.on(PutItemCommand).resolves({});
    vi.clearAllMocks();
  });

  const baseDeps = {
    dynamodb: new DynamoDBClient({}),
    tableName: "test-session-payload",
    logger: mockLogger as any,
    metrics: mockMetrics as any,
  };

  it("should write gzip-compressed payload to DynamoDB", async () => {
    await writeSessionPayload(
      {
        sessionId: "session-123",
        rawPayload: basePayload as any,
        matchResult: baseMatchResult,
        anomalies: [],
      },
      baseDeps,
    );

    const putCalls = dynamoMock.commandCalls(PutItemCommand);
    expect(putCalls).toHaveLength(1);
    expect(putCalls[0].args[0].input.Item!.session_id.S).toBe("session-123");
    expect(putCalls[0].args[0].input.Item!.payload_gzip_b64.S).toBeDefined();
  });

  it("should handle write errors gracefully (not throw)", async () => {
    dynamoMock.on(PutItemCommand).rejects(new Error("DynamoDB error"));

    await writeSessionPayload(
      {
        sessionId: "session-123",
        rawPayload: basePayload as any,
        matchResult: baseMatchResult,
        anomalies: [],
      },
      baseDeps,
    );

    expect(mockMetrics.addMetric).toHaveBeenCalledWith(
      "SessionPayloadWriteError",
      expect.any(String),
      1,
    );
  });
});
