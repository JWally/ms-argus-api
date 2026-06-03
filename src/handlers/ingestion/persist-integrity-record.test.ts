/**
 * Coverage for persistIntegrityRecord's idempotent-retry behavior.
 *
 * The SDK mints ONE session_id per scan and shares it across its worker
 * submission and the in-iframe fallback submission (see ms-argus-web-integrity
 * index-iframe.ts). When the worker path is abandoned after its POST already
 * landed, the fallback re-POSTs the same (cpi, session_id). The DDB write then
 * fails its `attribute_not_exists(cpi)` condition — but that's a duplicate of
 * an already-committed session, NOT a distinct replay. We must surface it as
 * an idempotent retry (duplicate:true, HTTP 200 upstream), not a 409.
 *
 * This was the companion fix to the STUN single-use idempotency
 * (stun-nonce-tracker.ts `existing.sessionId === sessionId`); without it the
 * 409 simply relocated from the STUN claim to the DDB conditional put.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockSend = vi.fn();

vi.mock("@aws-sdk/client-dynamodb", async () => {
  const actual = await vi.importActual<
    typeof import("@aws-sdk/client-dynamodb")
  >("@aws-sdk/client-dynamodb");
  return {
    ...actual,
    DynamoDBClient: class {
      send = (...args: unknown[]) => mockSend(...args);
    },
  };
});

// Firehose archive runs in the same Promise.all as the DDB put. It never
// throws in prod (errors are logged inside the helper); stub it so the test
// exercises only the DDB outcome.
vi.mock("../../helpers/firehose-archive", () => ({
  archiveToFirehose: vi.fn().mockResolvedValue(undefined),
}));

import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { persistIntegrityRecord } from "./base-handler";
import { HttpError } from "../../helpers/http-error";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { Metrics } from "@aws-lambda-powertools/metrics";

const mockLogger = {
  warn: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

const mockMetrics = {
  addMetric: vi.fn(),
} as unknown as Metrics;

type Ctx = Parameters<typeof persistIntegrityRecord>[0];

function makeCtx(): Ctx {
  return {
    cpi: "argus_cpi_test_abc",
    sessionId: "shared-session-123",
    deps: { logger: mockLogger, metrics: mockMetrics },
  } as unknown as Ctx;
}

function metricNames(): string[] {
  return vi.mocked(mockMetrics.addMetric).mock.calls.map((c) => c[0] as string);
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("persistIntegrityRecord", () => {
  it("fresh write: returns duplicate=false and issues a conditional PutItem", async () => {
    mockSend.mockResolvedValueOnce({});

    const result = await persistIntegrityRecord(makeCtx(), { foo: "bar" });

    expect(result).toEqual({ duplicate: false });
    const put = mockSend.mock.calls[0][0];
    // Idempotency hinges on this condition — assert it's still here so a
    // refactor can't silently turn the put into a blind overwrite.
    expect(put.input.ConditionExpression).toBe("attribute_not_exists(cpi)");
    expect(metricNames()).not.toContain("IntegrityIdempotentRetry");
  });

  it("duplicate (cpi, session_id): returns duplicate=true instead of throwing 409", async () => {
    mockSend.mockRejectedValueOnce(
      new ConditionalCheckFailedException({
        $metadata: {},
        message: "The conditional request failed",
      }),
    );

    // The bug this guards: a same-session re-submit must NOT 409.
    const result = await persistIntegrityRecord(makeCtx(), { foo: "bar" });

    expect(result).toEqual({ duplicate: true });
    expect(metricNames()).toContain("IntegrityIdempotentRetry");
    expect(mockLogger.info).toHaveBeenCalled();
  });

  it("does not emit IntegrityWriteFailed on the duplicate path", async () => {
    mockSend.mockRejectedValueOnce(
      new ConditionalCheckFailedException({ $metadata: {}, message: "dup" }),
    );

    await persistIntegrityRecord(makeCtx(), { foo: "bar" });

    expect(metricNames()).not.toContain("IntegrityWriteFailed");
  });

  it("genuine DDB error: throws HttpError(503) and meters IntegrityWriteFailed", async () => {
    mockSend.mockRejectedValueOnce(
      Object.assign(new Error("ProvisionedThroughputExceededException"), {
        name: "ProvisionedThroughputExceededException",
      }),
    );

    let caught: unknown;
    try {
      await persistIntegrityRecord(makeCtx(), { foo: "bar" });
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).statusCode).toBe(503);
    expect(metricNames()).toContain("IntegrityWriteFailed");
    expect(metricNames()).not.toContain("IntegrityIdempotentRetry");
  });
});
