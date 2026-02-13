import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../vector/embedding", () => ({
  computeEmbedding: vi.fn().mockReturnValue({
    vector: Array(512).fill(0.5),
    dimensions: 512,
  }),
  assessEmbeddingQuality: vi.fn().mockReturnValue({
    acceptable: true,
    score: 0.8,
    structuralCount: 5,
    renderingCount: 3,
    hardwareCount: 2,
  }),
  EMBEDDING_DIMENSIONS: 512,
}));

vi.mock("./profile-loader", () => ({
  loadProfile: vi.fn().mockResolvedValue(null),
}));

import { mockClient } from "aws-sdk-client-mock";
import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  vectorMatchWithTimeout,
  upsertDeviceVector,
  buildMobileScreenFilter,
} from "./vector-match";
import type { VectorMatchDeps } from "./vector-match";
import { loadProfile } from "./profile-loader";
import { assessEmbeddingQuality } from "../vector/embedding";
import { MatchTier } from "../../types/matching-tiers";

const lambdaMock = mockClient(LambdaClient);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const asPayload = (data: unknown): any =>
  new TextEncoder().encode(JSON.stringify(data));
const dynamoMock = mockClient(DynamoDBClient);

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

const mockMetrics = {
  addMetric: vi.fn(),
};

function createDeps(): VectorMatchDeps {
  return {
    lambda: new LambdaClient({}),
    dynamodb: new DynamoDBClient({}),
    vectorWorkerArn: "arn:aws:lambda:us-east-1:123:function:vector-worker",
    collection: "fingerprints_v2",
    profilesTable: "test-profiles",
    logger: mockLogger as any,
    metrics: mockMetrics as any,
  };
}

const fingerprint = {
  stable_hash: "hash-abc",
  fuzzy_hash: "fuzzy-def",
  canvas_hash: "canvas-123",
  webgl_hash: "webgl-456",
  gpu_renderer: "NVIDIA",
  audio_hash: "audio-789",
  user_agent: "Mozilla/5.0",
  screen_dims: "1920x1080",
  hardware_concurrency: 8,
  ip_address: "1.1.1.1",
  asn: 100,
} as any;

describe("vectorMatchWithTimeout", () => {
  beforeEach(() => {
    lambdaMock.reset();
    dynamoMock.reset();
    vi.clearAllMocks();
  });

  it("should return match result from successful search", async () => {
    const searchResponse = {
      success: true,
      results: [
        { device_id: "dev_001", score: 0.92, payload: {} },
        { device_id: "dev_002", score: 0.8, payload: {} },
      ],
      count: 2,
      top_score: 0.92,
      duration_ms: 50,
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(searchResponse),
    });

    const deps = createDeps();
    const { result, timedOut } = await vectorMatchWithTimeout(
      deps,
      fingerprint,
    );

    expect(timedOut).toBe(false);
    expect(result).not.toBeNull();
    expect(result!.device_id).toBe("dev_001");
    expect(result!.match_tier).toBe(MatchTier.VECTOR);
    expect(result!.evidence_codes).toContain("VECTOR_SIMILARITY");
    expect(result!.evidence_codes).toContain("HIGH_SIMILARITY"); // score >= 0.9
  });

  it("should return null when no matches found", async () => {
    const searchResponse = {
      success: true,
      results: [],
      count: 0,
      top_score: null,
      duration_ms: 30,
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(searchResponse),
    });

    const deps = createDeps();
    const { result, timedOut } = await vectorMatchWithTimeout(
      deps,
      fingerprint,
    );

    expect(timedOut).toBe(false);
    expect(result).toBeNull();
  });

  it("should return null on Lambda error", async () => {
    lambdaMock.on(InvokeCommand).resolves({
      FunctionError: "Unhandled",
      Payload: asPayload({ errorMessage: "timeout" }),
    });

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);
    expect(result).toBeNull();
  });

  it("should return null when Lambda returns empty payload", async () => {
    lambdaMock.on(InvokeCommand).resolves({
      Payload: undefined,
    });

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);
    expect(result).toBeNull();
  });

  it("should handle COLLECTION_NOT_FOUND error gracefully", async () => {
    const errorResponse = {
      success: false,
      error: "Collection not found",
      code: "COLLECTION_NOT_FOUND",
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(errorResponse),
    });

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);
    expect(result).toBeNull();
  });

  it("should handle generic search error", async () => {
    const errorResponse = {
      success: false,
      error: "Qdrant timeout",
      code: "QDRANT_ERROR",
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(errorResponse),
    });

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);
    expect(result).toBeNull();
  });

  it("should include IP history context when profile has IP history", async () => {
    vi.mocked(loadProfile).mockResolvedValueOnce({
      ip_history: [{ ip: "1.1.1.1", asn: 100, ts: Date.now() }],
      risk_score: 0.2,
      flags: [],
      fuzzy_hash: "fuzzy-456",
    } as any);

    const searchResponse = {
      success: true,
      results: [{ device_id: "dev_001", score: 0.85, payload: {} }],
      count: 1,
      top_score: 0.85,
      duration_ms: 50,
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(searchResponse),
    });

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);

    expect(result).not.toBeNull();
    expect(result!.ip_history_context).toBeDefined();
    expect(result!.ip_history_context!.known_ip).toBe(true);
  });

  it("should handle Lambda invocation errors", async () => {
    lambdaMock.on(InvokeCommand).rejects(new Error("network error"));

    const deps = createDeps();
    const { result } = await vectorMatchWithTimeout(deps, fingerprint);
    expect(result).toBeNull();
  });
});

describe("upsertDeviceVector", () => {
  beforeEach(() => {
    lambdaMock.reset();
    vi.clearAllMocks();
  });

  it("should skip upsert when quality gate fails", async () => {
    vi.mocked(assessEmbeddingQuality).mockReturnValueOnce({
      acceptable: false,
      score: 0.2,
      structuralCount: 1,
      renderingCount: 0,
      hardwareCount: 0,
      reason: "Too few features",
    } as any);

    const deps = createDeps();
    const result = await upsertDeviceVector(deps, "dev_001", fingerprint);
    expect(result).toBe(false);
    expect(lambdaMock.commandCalls(InvokeCommand)).toHaveLength(0);
  });

  it("should upsert successfully", async () => {
    const upsertResponse = {
      success: true,
      device_id: "dev_001",
      duration_ms: 30,
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(upsertResponse),
    });

    const deps = createDeps();
    const result = await upsertDeviceVector(deps, "dev_001", fingerprint);
    expect(result).toBe(true);
  });

  it("should return false when upsert response indicates failure", async () => {
    const errorResponse = {
      success: false,
      error: "Qdrant error",
      code: "QDRANT_ERROR",
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(errorResponse),
    });

    const deps = createDeps();
    const result = await upsertDeviceVector(deps, "dev_001", fingerprint);
    expect(result).toBe(false);
  });

  it("should return false when Lambda returns null response", async () => {
    lambdaMock.on(InvokeCommand).resolves({
      FunctionError: "Unhandled",
      Payload: asPayload("error"),
    });

    const deps = createDeps();
    const result = await upsertDeviceVector(deps, "dev_001", fingerprint);
    expect(result).toBe(false);
  });

  it("should return false on invocation error", async () => {
    lambdaMock.on(InvokeCommand).rejects(new Error("timeout"));

    const deps = createDeps();
    const result = await upsertDeviceVector(deps, "dev_001", fingerprint);
    expect(result).toBe(false);
  });

  it("should include screen and platform metadata in upsert payload", async () => {
    const upsertResponse = {
      success: true,
      device_id: "dev_001",
      duration_ms: 30,
    };

    lambdaMock.on(InvokeCommand).resolves({
      Payload: asPayload(upsertResponse),
    });

    const deps = createDeps();
    const fp = {
      ...fingerprint,
      screen_dims: "393x852",
      platform: "iPhone",
    };
    await upsertDeviceVector(deps, "dev_001", fp);

    const invokeCall = lambdaMock.commandCalls(InvokeCommand)[0];
    const payload = JSON.parse(
      Buffer.from(invokeCall.args[0].input.Payload as Uint8Array).toString(),
    );
    expect(payload.payload.screen_width).toBe(393);
    expect(payload.payload.screen_height).toBe(852);
    expect(payload.payload.platform).toBe("iPhone");
  });
});

describe("buildMobileScreenFilter", () => {
  it("should return range filter for iPhone", () => {
    const filter = buildMobileScreenFilter({
      screen_dims: "393x852",
      platform: "iPhone",
    } as any);

    expect(filter).toEqual({
      must: [
        { key: "screen_width", range: { gte: 388, lte: 398 } },
        { key: "screen_height", range: { gte: 847, lte: 857 } },
      ],
    });
  });

  it("should return range filter for iPad", () => {
    const filter = buildMobileScreenFilter({
      screen_dims: "1024x1366",
      platform: "iPad",
    } as any);

    expect(filter).toBeDefined();
    expect(filter!.must).toHaveLength(2);
  });

  it("should return undefined for desktop platform", () => {
    const filter = buildMobileScreenFilter({
      screen_dims: "1920x1080",
      platform: "MacIntel",
    } as any);

    expect(filter).toBeUndefined();
  });

  it("should return undefined when platform is missing", () => {
    const filter = buildMobileScreenFilter({
      screen_dims: "393x852",
    } as any);

    expect(filter).toBeUndefined();
  });

  it("should return undefined when screen_dims is missing", () => {
    const filter = buildMobileScreenFilter({
      platform: "iPhone",
    } as any);

    expect(filter).toBeUndefined();
  });

  it("should return undefined for invalid screen_dims format", () => {
    const filter = buildMobileScreenFilter({
      screen_dims: "invalid",
      platform: "iPhone",
    } as any);

    expect(filter).toBeUndefined();
  });
});
