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

const mockArchiveToFirehose = vi.hoisted(() => vi.fn());

// Firehose archive is started before the DDB put but does not gate it. Stub it
// so the tests can control archival independently from the durable write.
vi.mock("../../helpers/firehose-archive", () => ({
  archiveToFirehose: mockArchiveToFirehose,
}));

import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import {
  persistIntegrityRecord,
  type PersistIntegrityRecordDeps,
} from "./persist-integrity-record";
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
const mockSend = vi.fn();
const persistDeps = {
  dynamo: { send: mockSend },
  tableName: "integrity-results-test",
  firehoseStreamName: "integrity-firehose-test",
} as PersistIntegrityRecordDeps;

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
  mockArchiveToFirehose.mockResolvedValue(true);
});

describe("persistIntegrityRecord", () => {
  it("fresh write: returns duplicate=false and issues a conditional PutItem", async () => {
    mockSend.mockResolvedValueOnce({});

    const result = await persistIntegrityRecord(
      makeCtx(),
      { foo: "bar" },
      persistDeps,
    );

    expect(result).toEqual({ duplicate: false });
    const put = mockSend.mock.calls[0][0];
    // Idempotency hinges on this condition — assert it's still here so a
    // refactor can't silently turn the put into a blind overwrite.
    expect(put.input.ConditionExpression).toBe("attribute_not_exists(cpi)");
    expect(put.input.TableName).toBe("integrity-results-test");
    expect(mockArchiveToFirehose).toHaveBeenCalledWith(
      { foo: "bar" },
      expect.objectContaining({ streamName: "integrity-firehose-test" }),
    );
    expect(metricNames()).not.toContain("IntegrityIdempotentRetry");
  });

  it("does not hold the client response on best-effort Firehose archival", async () => {
    let finishArchive!: (value: boolean) => void;
    mockArchiveToFirehose.mockReturnValueOnce(
      new Promise<boolean>((resolve) => {
        finishArchive = resolve;
      }),
    );
    mockSend.mockResolvedValueOnce({});

    const pending = persistIntegrityRecord(
      makeCtx(),
      { foo: "bar" },
      persistDeps,
    );
    expect(mockSend).toHaveBeenCalledOnce();
    await expect(pending).resolves.toEqual({ duplicate: false });

    finishArchive(true);
    await Promise.resolve();
  });

  it("still succeeds when best-effort Firehose archival rejects", async () => {
    mockArchiveToFirehose.mockRejectedValueOnce(new Error("firehose down"));
    mockSend.mockResolvedValueOnce({});

    await expect(
      persistIntegrityRecord(makeCtx(), { foo: "bar" }, persistDeps),
    ).resolves.toEqual({ duplicate: false });
  });

  it("duplicate (cpi, session_id): returns duplicate=true instead of throwing 409", async () => {
    mockSend.mockRejectedValueOnce(
      new ConditionalCheckFailedException({
        $metadata: {},
        message: "The conditional request failed",
      }),
    );

    // The bug this guards: a same-session re-submit must NOT 409.
    const result = await persistIntegrityRecord(
      makeCtx(),
      { foo: "bar" },
      persistDeps,
    );

    expect(result).toEqual({ duplicate: true });
    expect(metricNames()).toContain("IntegrityIdempotentRetry");
    expect(mockLogger.info).toHaveBeenCalled();
  });

  it("does not emit IntegrityWriteFailed on the duplicate path", async () => {
    mockSend.mockRejectedValueOnce(
      new ConditionalCheckFailedException({ $metadata: {}, message: "dup" }),
    );

    await persistIntegrityRecord(makeCtx(), { foo: "bar" }, persistDeps);

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
      await persistIntegrityRecord(makeCtx(), { foo: "bar" }, persistDeps);
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).statusCode).toBe(503);
    expect(metricNames()).toContain("IntegrityWriteFailed");
    expect(metricNames()).not.toContain("IntegrityIdempotentRetry");
  });
});
