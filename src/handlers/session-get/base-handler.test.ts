import { describe, it, expect, vi, beforeEach } from "vitest";

const mockVerify = vi.fn();
vi.mock("../../helpers/token-verifier", () => ({
  verifyMerchantToken: (...args: unknown[]) => mockVerify(...args),
}));

const mockDecrement = vi.fn();
vi.mock("../../helpers/credits", () => ({
  decrementCredit: (...args: unknown[]) => mockDecrement(...args),
}));

const mockFetchIntegrity = vi.fn();
vi.mock("./session-ops", () => ({
  extractSessionId: (event: { pathParameters?: { session_id?: string } }) =>
    event.pathParameters?.session_id ?? "sid-1",
  fetchIntegrityResultsByComposite: (...args: unknown[]) =>
    mockFetchIntegrity(...args),
}));

const mockBuildMerchant = vi.fn();
vi.mock("../../helpers/merchant-projection", () => ({
  buildMerchantResponse: (...args: unknown[]) => mockBuildMerchant(...args),
}));

const mockVerifySdkAttestation = vi.fn();
vi.mock("../../helpers/sdk-attestation", () => ({
  parseSdkAttestationHeaders: (headers: Record<string, string> | undefined) =>
    headers?.["x-argus-attest-envelope"]
      ? {
          envelope: headers["x-argus-attest-envelope"],
          signature: headers["x-argus-attest-signature"],
          publicKey: headers["x-argus-attest-public-key"],
          keyId: headers["x-argus-attest-key-id"],
        }
      : null,
  verifySdkAttestation: (...args: unknown[]) =>
    mockVerifySdkAttestation(...args),
}));

import { createBaseHandler } from "./base-handler";

const logger = {
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
} as unknown as import("@aws-lambda-powertools/logger").Logger;
const metrics = {
  addMetric: vi.fn(),
} as unknown as import("@aws-lambda-powertools/metrics").Metrics;

const deps = {
  dynamodb: {} as import("@aws-sdk/client-dynamodb").DynamoDBClient,
  integrityResultsTable: "integrity",
  merchantsTable: "merchants",
  logger,
  metrics,
};

const handler = createBaseHandler(deps);

const validCpi = "argus_cpi_test_abc1234567890";

beforeEach(() => {
  vi.clearAllMocks();
  process.env.PLATFORM_PUBKEY_SSM_PATH =
    "/argus-platform/dev-jw/api-signing-pubkey";
});

function makeEvent(overrides: {
  cpi?: string;
  sessionId?: string;
  method?: string;
  headers?: Record<string, string>;
}): import("aws-lambda").APIGatewayProxyEvent {
  return {
    httpMethod: overrides.method ?? "GET",
    pathParameters: {
      cpi: overrides.cpi ?? validCpi,
      session_id: overrides.sessionId ?? "sid-1",
    },
    headers: overrides.headers ?? {
      "x-api-key": "k1",
      "x-argus-token": "t1",
    },
  } as unknown as import("aws-lambda").APIGatewayProxyEvent;
}

describe("session-get base handler", () => {
  it("short-circuits OPTIONS preflight with 204", async () => {
    const result = await handler(makeEvent({ method: "OPTIONS" }));
    expect((result as { statusCode: number }).statusCode).toBe(204);
    expect(mockVerify).not.toHaveBeenCalled();
  });

  it("returns 400 on malformed cpi", async () => {
    const result = await handler(makeEvent({ cpi: "not-a-cpi" }));
    expect((result as { statusCode: number }).statusCode).toBe(400);
    expect(mockVerify).not.toHaveBeenCalled();
  });

  it("returns 401 when token verification fails", async () => {
    mockVerify.mockResolvedValueOnce(null);
    const result = await handler(makeEvent({}));
    expect((result as { statusCode: number }).statusCode).toBe(401);
    expect(mockDecrement).not.toHaveBeenCalled();
  });

  it("returns 402 when credit decrement fails — does NOT touch integrity store", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockDecrement.mockResolvedValueOnce({
      ok: false,
      reason: "insufficient_credits",
    });
    const result = (await handler(makeEvent({}))) as {
      statusCode: number;
      body: string;
    };
    expect(result.statusCode).toBe(402);
    expect(JSON.parse(result.body)).toEqual({ error: "insufficient_credits" });
    expect(mockFetchIntegrity).not.toHaveBeenCalled();
  });

  it("returns 404 when session is not found (credit already burned)", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockDecrement.mockResolvedValueOnce({ ok: true, remaining: 99 });
    mockFetchIntegrity.mockResolvedValueOnce(undefined);
    const result = (await handler(makeEvent({}))) as { statusCode: number };
    expect(result.statusCode).toBe(404);
  });

  it("returns 200 with merchant body + creditsRemaining on the happy path", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockDecrement.mockResolvedValueOnce({ ok: true, remaining: 1999 });
    mockFetchIntegrity.mockResolvedValueOnce({ created_at: 0 });
    mockBuildMerchant.mockReturnValueOnce({
      session_id: "sid-1",
      verdict: "clean",
    });
    const result = (await handler(makeEvent({}))) as {
      statusCode: number;
      body: string;
    };
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body)).toMatchObject({
      session_id: "sid-1",
      verdict: "clean",
      creditsRemaining: 1999,
    });
    expect(mockVerifySdkAttestation).not.toHaveBeenCalled();
  });

  it("verifies optional SDK attestation before returning a merchant verdict", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockVerifySdkAttestation.mockReturnValueOnce({
      ok: true,
      keyId: "device-key-1",
      publicKey: "pub",
      payload: { cpi: validCpi, sessionId: "sid-1", checkoutNonce: "co-1" },
    });
    mockDecrement.mockResolvedValueOnce({ ok: true, remaining: 1998 });
    mockFetchIntegrity.mockResolvedValueOnce({
      created_at: 0,
      identification: { pubkey: "pub", verified: true },
    });
    mockBuildMerchant.mockReturnValueOnce({
      session_id: "sid-1",
      verdict: "clean",
    });

    const result = (await handler(
      makeEvent({
        headers: {
          "x-api-key": "k1",
          "x-argus-token": "t1",
          "x-argus-attest-envelope": "env",
          "x-argus-attest-signature": "sig",
          "x-argus-attest-public-key": "pub",
          "x-argus-attest-key-id": "device-key-1",
        },
      }),
    )) as { statusCode: number; body: string };

    expect(result.statusCode).toBe(200);
    expect(mockVerifySdkAttestation).toHaveBeenCalledWith(
      {
        envelope: "env",
        signature: "sig",
        publicKey: "pub",
        keyId: "device-key-1",
      },
      {
        expectedPurpose: "argus-session-get-v1",
        expectedCpi: validCpi,
        expectedSessionId: "sid-1",
      },
    );
    expect(JSON.parse(result.body)).toMatchObject({
      session_id: "sid-1",
      verdict: "clean",
      attestation: {
        verified: true,
        keyId: "device-key-1",
        payload: { cpi: validCpi, sessionId: "sid-1", checkoutNonce: "co-1" },
      },
    });
  });

  it("rejects an invalid SDK attestation before burning merchant credit", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockVerifySdkAttestation.mockReturnValueOnce({
      ok: false,
      reason: "session_mismatch",
    });

    const result = (await handler(
      makeEvent({
        headers: {
          "x-api-key": "k1",
          "x-argus-token": "t1",
          "x-argus-attest-envelope": "env",
          "x-argus-attest-signature": "sig",
          "x-argus-attest-public-key": "pub",
          "x-argus-attest-key-id": "device-key-1",
        },
      }),
    )) as { statusCode: number; body: string };

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body)).toEqual({
      error: "Invalid attestation",
      reason: "session_mismatch",
    });
    expect(mockDecrement).not.toHaveBeenCalled();
  });

  it("rejects a valid SDK attestation from a different device key than the stored scan", async () => {
    mockVerify.mockResolvedValueOnce({
      merchantId: "m1",
      cpi: validCpi,
      keyId: "k1",
      plan: "free",
      iat: 0,
    });
    mockVerifySdkAttestation.mockReturnValueOnce({
      ok: true,
      keyId: "device-key-1",
      publicKey: "pub-from-attestation",
      payload: { cpi: validCpi, sessionId: "sid-1" },
    });
    mockDecrement.mockResolvedValueOnce({ ok: true, remaining: 1997 });
    mockFetchIntegrity.mockResolvedValueOnce({
      identification: { pubkey: "pub-from-scan", verified: true },
    });

    const result = (await handler(
      makeEvent({
        headers: {
          "x-api-key": "k1",
          "x-argus-token": "t1",
          "x-argus-attest-envelope": "env",
          "x-argus-attest-signature": "sig",
          "x-argus-attest-public-key": "pub-from-attestation",
          "x-argus-attest-key-id": "device-key-1",
        },
      }),
    )) as { statusCode: number; body: string };

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body)).toEqual({
      error: "Invalid attestation",
      reason: "public_key_mismatch",
    });
    expect(mockBuildMerchant).not.toHaveBeenCalled();
  });

  it("returns 500 when PLATFORM_PUBKEY_SSM_PATH is missing", async () => {
    delete process.env.PLATFORM_PUBKEY_SSM_PATH;
    const result = (await handler(makeEvent({}))) as { statusCode: number };
    expect(result.statusCode).toBe(500);
  });
});
