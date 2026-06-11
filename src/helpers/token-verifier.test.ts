import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";

const mockSsmSend = vi.fn();
vi.mock("@aws-sdk/client-ssm", () => ({
  SSMClient: class {
    send = (...args: unknown[]) => mockSsmSend(...args);
  },
  GetParameterCommand: class {
    constructor(public input: unknown) {}
  },
}));

import { verifyMerchantToken, __testing__ } from "./token-verifier";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

function base64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function makeToken(claims: Record<string, unknown>): string {
  const encoded = base64url(Buffer.from(JSON.stringify(claims), "utf8"));
  const sig = cryptoSign(null, Buffer.from(encoded, "utf8"), privateKey);
  return `${encoded}.${base64url(sig)}`;
}

const SSM_PATH = "/argus-platform/dev-jw/api-signing-pubkey";

beforeEach(() => {
  vi.clearAllMocks();
  __testing__.resetCache();
});

describe("verifyMerchantToken", () => {
  it("verifies when keyId header + signed token match the claims", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const token = makeToken(claims);
    const verified = await verifyMerchantToken(claims.keyId, token, {
      ssmPubkeyPath: SSM_PATH,
    });
    expect(verified).toEqual(claims);
  });

  it("rejects when path's expectedCpi does not match the claim", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const verified = await verifyMerchantToken(
      claims.keyId,
      makeToken(claims),
      {
        ssmPubkeyPath: SSM_PATH,
        expectedCpi: "argus_cpi_test_DIFFERENT_PATH_CPI",
      },
    );
    expect(verified).toBeNull();
  });

  it("rejects when x-api-key header does not match claims.keyId", async () => {
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_realKey1234567",
      plan: "free",
      iat: 1700000000,
    };
    const verified = await verifyMerchantToken(
      "argus_sk_test_DIFFERENTID",
      makeToken(claims),
      { ssmPubkeyPath: SSM_PATH },
    );
    expect(verified).toBeNull();
  });

  it("rejects on tampered signature", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const token = makeToken(claims);
    const [encoded, sig] = token.split(".");
    const tampered = `${encoded.slice(0, -1)}A.${sig}`;
    const verified = await verifyMerchantToken(claims.keyId, tampered, {
      ssmPubkeyPath: SSM_PATH,
    });
    expect(verified).toBeNull();
  });

  it("rejects on missing or malformed headers", async () => {
    expect(
      await verifyMerchantToken(undefined, "a.b", { ssmPubkeyPath: SSM_PATH }),
    ).toBeNull();
    expect(
      await verifyMerchantToken("k", undefined, { ssmPubkeyPath: SSM_PATH }),
    ).toBeNull();
    expect(
      await verifyMerchantToken("k", "only-one-segment", {
        ssmPubkeyPath: SSM_PATH,
      }),
    ).toBeNull();
    expect(
      await verifyMerchantToken("k", "a.b.c", { ssmPubkeyPath: SSM_PATH }),
    ).toBeNull();
  });

  it("caches the public key so repeated verifies hit SSM once", async () => {
    mockSsmSend.mockResolvedValue({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const token = makeToken(claims);
    await verifyMerchantToken(claims.keyId, token, { ssmPubkeyPath: SSM_PATH });
    await verifyMerchantToken(claims.keyId, token, { ssmPubkeyPath: SSM_PATH });
    expect(mockSsmSend).toHaveBeenCalledTimes(1);
  });

  it("stale-while-revalidate: a stale key is served immediately and refreshed in the background", async () => {
    vi.useFakeTimers();
    try {
      mockSsmSend.mockResolvedValue({ Parameter: { Value: publicPem } });
      const claims = {
        merchantId: "m1",
        cpi: "argus_cpi_test_xyz1234567890",
        keyId: "argus_sk_test_abc1234567890",
        plan: "free",
        iat: 1700000000,
      };
      const token = makeToken(claims);

      // First call primes the cache (1 SSM read).
      const r1 = await verifyMerchantToken(claims.keyId, token, {
        ssmPubkeyPath: SSM_PATH,
      });
      expect(r1).not.toBeNull();
      expect(mockSsmSend).toHaveBeenCalledTimes(1);

      // Advance past the 1h TTL so the cached key is now stale.
      vi.advanceTimersByTime(61 * 60 * 1000);

      // Next call still resolves immediately with a valid result (served the
      // stale key) and kicks off exactly one background refresh.
      const r2 = await verifyMerchantToken(claims.keyId, token, {
        ssmPubkeyPath: SSM_PATH,
      });
      expect(r2).not.toBeNull();
      await vi.runAllTimersAsync(); // let the background refresh settle
      expect(mockSsmSend).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
