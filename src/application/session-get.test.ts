import { beforeEach, describe, expect, it, vi } from "vitest";
import { createSessionGet, type SessionGetPorts } from "./session-get";

const validCpi = "argus_cpi_test_abc1234567890";
const claims = {
  merchantId: "merchant-1",
  cpi: validCpi,
  keyId: "key-1",
  plan: "test",
  iat: 1,
};
const verifiedAttestation = {
  ok: true as const,
  keyId: "device-key-1",
  publicKey: "device-public-key",
  payload: { cpi: validCpi, sessionId: "session-1" },
};

function createPorts(): SessionGetPorts {
  return {
    verifyMerchant: vi.fn().mockResolvedValue(claims),
    verifyAttestation: vi.fn().mockReturnValue(verifiedAttestation),
    debitCredit: vi.fn().mockResolvedValue({ ok: true, remaining: 9 }),
    fetchIntegrity: vi.fn().mockResolvedValue({
      created_at: 1,
      identification: {
        pubkey: "device-public-key",
        verified: true,
        reason: null,
        sig_present: true,
      },
    }),
    buildProjection: vi.fn().mockReturnValue({
      schema_version: 1,
      session_id: "session-1",
      verdict: "clean",
    }),
    now: vi
      .fn()
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(110)
      .mockReturnValueOnce(115)
      .mockReturnValueOnce(130)
      .mockReturnValueOnce(150)
      .mockReturnValueOnce(155),
    recordMetric: vi.fn(),
    logTiming: vi.fn(),
  };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    cpi: validCpi,
    sessionId: "session-1",
    apiKey: "key-1",
    merchantToken: "token-1",
    attestation: {
      envelope: "envelope",
      signature: "signature",
      publicKey: "device-public-key",
      keyId: "device-key-1",
    },
    ...overrides,
  };
}

describe("session-get application core", () => {
  let ports: SessionGetPorts;

  beforeEach(() => {
    ports = createPorts();
  });

  it("fails closed when the merchant verifier is not configured", async () => {
    const getSession = createSessionGet({ ports });

    await expect(getSession(request())).resolves.toEqual({
      kind: "verifier_misconfigured",
    });
    expect(ports.verifyMerchant).not.toHaveBeenCalled();
    expect(ports.debitCredit).not.toHaveBeenCalled();
  });

  it("rejects an invalid merchant before attestation or billing", async () => {
    vi.mocked(ports.verifyMerchant).mockResolvedValueOnce(null);
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "unauthorized",
    });
    expect(ports.verifyAttestation).not.toHaveBeenCalled();
    expect(ports.debitCredit).not.toHaveBeenCalled();
  });

  it("rejects invalid SDK attestation before burning credit", async () => {
    vi.mocked(ports.verifyAttestation).mockReturnValueOnce({
      ok: false,
      reason: "session_mismatch",
    });
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "invalid_attestation",
      reason: "session_mismatch",
    });
    expect(ports.debitCredit).not.toHaveBeenCalled();
  });

  it("returns insufficient credit without reading the integrity store", async () => {
    vi.mocked(ports.debitCredit).mockResolvedValueOnce({
      ok: false,
      reason: "insufficient_credits",
    });
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "insufficient_credits",
    });
    expect(ports.fetchIntegrity).not.toHaveBeenCalled();
  });

  it("returns not found after the billable read is debited", async () => {
    vi.mocked(ports.fetchIntegrity).mockResolvedValueOnce(undefined);
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "not_found",
    });
    expect(ports.debitCredit).toHaveBeenCalledWith("merchant-1");
  });

  it("requires the current identification public key for attested reads", async () => {
    vi.mocked(ports.fetchIntegrity).mockResolvedValueOnce({
      created_at: 1,
      identifiers: { public_key: "retired-row-key" },
      device_identity: { pubkey: "retired-device-key" },
    } as never);
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "invalid_attestation",
      reason: "stored_public_key_missing",
    });
    expect(ports.buildProjection).not.toHaveBeenCalled();
  });

  it("rejects an attestation bound to a different current device key", async () => {
    vi.mocked(ports.fetchIntegrity).mockResolvedValueOnce({
      created_at: 1,
      identification: {
        pubkey: "different-key",
        verified: true,
        reason: null,
        sig_present: true,
      },
    } as never);
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "invalid_attestation",
      reason: "public_key_mismatch",
    });
    expect(ports.buildProjection).not.toHaveBeenCalled();
  });

  it("returns an unattested projection without inventing attestation data", async () => {
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(
      getSession(request({ attestation: undefined })),
    ).resolves.toEqual({
      kind: "ok",
      projection: {
        schema_version: 1,
        session_id: "session-1",
        verdict: "clean",
      },
      creditsRemaining: 9,
    });
    expect(ports.verifyAttestation).not.toHaveBeenCalled();
  });

  it("returns the projected session and records ordered phase timing", async () => {
    const getSession = createSessionGet({
      ssmPubkeyPath: "/platform/pubkey",
      ports,
    });

    await expect(getSession(request())).resolves.toEqual({
      kind: "ok",
      projection: {
        schema_version: 1,
        session_id: "session-1",
        verdict: "clean",
      },
      creditsRemaining: 9,
      attestation: verifiedAttestation,
    });
    expect(ports.logTiming).toHaveBeenCalledWith({
      authMs: 10,
      attestMs: 5,
      debitMs: 15,
      fetchMs: 20,
      projectMs: 5,
      totalMs: 55,
    });
    expect(ports.recordMetric).toHaveBeenCalledWith("MerchantTokenAccepted");
    expect(ports.recordMetric).toHaveBeenCalledWith("CreditBurned");
    expect(ports.recordMetric).toHaveBeenCalledWith("SdkAttestationAccepted");
    expect(ports.recordMetric).toHaveBeenCalledWith(
      "IntegritySessionRetrieved",
    );
  });
});
