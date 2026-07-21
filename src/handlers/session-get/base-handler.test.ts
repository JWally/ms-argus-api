import { beforeEach, describe, expect, it, vi } from "vitest";
import type { APIGatewayProxyEvent } from "aws-lambda";
import { createBaseHandler } from "./base-handler";

const logger = { error: vi.fn() };
const metrics = { addMetric: vi.fn() };
const getSession = vi.fn();
const handler = createBaseHandler({ logger, metrics, getSession });
const validCpi = "argus_cpi_test_abc1234567890";
type JsonResponse = { statusCode: number; body?: string };

function makeEvent(overrides: {
  cpi?: string;
  sessionId?: string;
  method?: string;
  headers?: Record<string, string>;
}): APIGatewayProxyEvent {
  return {
    httpMethod: overrides.method ?? "GET",
    pathParameters: {
      cpi: overrides.cpi ?? validCpi,
      session_id: overrides.sessionId ?? "session-1",
    },
    headers: overrides.headers ?? {
      "x-api-key": "key-1",
      "x-argus-token": "token-1",
    },
  } as unknown as APIGatewayProxyEvent;
}

describe("session-get HTTP adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("short-circuits OPTIONS without invoking the application", async () => {
    await expect(handler(makeEvent({ method: "OPTIONS" }))).resolves.toEqual({
      statusCode: 204,
    });
    expect(getSession).not.toHaveBeenCalled();
  });

  it("rejects a malformed CPI before invoking the application", async () => {
    const response = (await handler(
      makeEvent({ cpi: "not-a-cpi" }),
    )) as JsonResponse;
    expect(response.statusCode).toBe(400);
    expect(getSession).not.toHaveBeenCalled();
  });

  it("maps headers and optional attestation into the application request", async () => {
    getSession.mockResolvedValueOnce({
      kind: "ok",
      projection: { schema_version: 1, session_id: "session-1" },
      creditsRemaining: 8,
      attestation: {
        ok: true,
        keyId: "device-key-1",
        publicKey: "public-key",
        payload: { checkoutNonce: "checkout-1" },
      },
    });

    const response = (await handler(
      makeEvent({
        headers: {
          "X-Api-Key": "key-1",
          "X-Argus-Token": "token-1",
          "x-argus-attest-envelope": "envelope",
          "x-argus-attest-signature": "signature",
          "x-argus-attest-public-key": "public-key",
          "x-argus-attest-key-id": "device-key-1",
        },
      }),
    )) as JsonResponse;

    expect(getSession).toHaveBeenCalledWith({
      cpi: validCpi,
      sessionId: "session-1",
      apiKey: "key-1",
      merchantToken: "token-1",
      attestation: {
        envelope: "envelope",
        signature: "signature",
        publicKey: "public-key",
        keyId: "device-key-1",
      },
    });
    expect(JSON.parse(response.body as string)).toEqual({
      schema_version: 1,
      session_id: "session-1",
      attestation: {
        verified: true,
        keyId: "device-key-1",
        payload: { checkoutNonce: "checkout-1" },
      },
      creditsRemaining: 8,
    });
  });

  it.each([
    ["unauthorized", 401, { error: "Invalid or missing token" }],
    ["insufficient_credits", 402, { error: "insufficient_credits" }],
    ["not_found", 404, { error: "Session not found" }],
  ] as const)("maps %s into HTTP %i", async (kind, status, body) => {
    getSession.mockResolvedValueOnce({ kind });
    const response = (await handler(makeEvent({}))) as JsonResponse;
    expect(response.statusCode).toBe(status);
    expect(JSON.parse(response.body as string)).toEqual(body);
  });

  it("omits attestation from an unattested successful response", async () => {
    getSession.mockResolvedValueOnce({
      kind: "ok",
      projection: { schema_version: 1, session_id: "session-1" },
      creditsRemaining: 7,
    });
    const response = (await handler(makeEvent({}))) as JsonResponse;
    expect(JSON.parse(response.body as string)).toEqual({
      schema_version: 1,
      session_id: "session-1",
      creditsRemaining: 7,
    });
  });

  it("maps attestation failures with their machine-readable reason", async () => {
    getSession.mockResolvedValueOnce({
      kind: "invalid_attestation",
      reason: "public_key_mismatch",
    });
    const response = (await handler(makeEvent({}))) as JsonResponse;
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body as string)).toEqual({
      error: "Invalid attestation",
      reason: "public_key_mismatch",
    });
  });

  it("logs and maps missing verifier configuration", async () => {
    getSession.mockResolvedValueOnce({ kind: "verifier_misconfigured" });
    const response = (await handler(makeEvent({}))) as JsonResponse;
    expect(response.statusCode).toBe(500);
    expect(logger.error).toHaveBeenCalledWith(
      "PLATFORM_PUBKEY_SSM_PATH not configured",
    );
  });
});
