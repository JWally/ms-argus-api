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
  it("verifies a well-formed token and returns the claims", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const signed = makeToken(claims);
    const credential = `${claims.keyId}.${signed}`;
    const verified = await verifyMerchantToken(credential, {
      ssmPubkeyPath: SSM_PATH,
    });
    expect(verified).toEqual(claims);
  });

  it("rejects when the path's expectedCpi does not match the claim", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_abc1234567890",
      plan: "free",
      iat: 1700000000,
    };
    const credential = `${claims.keyId}.${makeToken(claims)}`;
    const verified = await verifyMerchantToken(credential, {
      ssmPubkeyPath: SSM_PATH,
      expectedCpi: "argus_cpi_test_DIFFERENT_PATH_CPI",
    });
    expect(verified).toBeNull();
  });

  it("rejects when keyId prefix does not match the keyId claim", async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: publicPem } });
    const claims = {
      merchantId: "m1",
      cpi: "argus_cpi_test_xyz1234567890",
      keyId: "argus_sk_test_realKey1234567",
      plan: "free",
      iat: 1700000000,
    };
    const credential = `argus_sk_test_DIFFERENTID.${makeToken(claims)}`;
    const verified = await verifyMerchantToken(credential, {
      ssmPubkeyPath: SSM_PATH,
    });
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
    const signed = makeToken(claims);
    // Flip a bit in the encoded claims so signature no longer matches.
    const [encoded, sig] = signed.split(".");
    const tampered = `${encoded.slice(0, -1)}A.${sig}`;
    const credential = `${claims.keyId}.${tampered}`;
    const verified = await verifyMerchantToken(credential, {
      ssmPubkeyPath: SSM_PATH,
    });
    expect(verified).toBeNull();
  });

  it("rejects on missing or malformed header", async () => {
    expect(
      await verifyMerchantToken(undefined, { ssmPubkeyPath: SSM_PATH }),
    ).toBeNull();
    expect(
      await verifyMerchantToken("only.two", { ssmPubkeyPath: SSM_PATH }),
    ).toBeNull();
    expect(
      await verifyMerchantToken("a.b.c.d", { ssmPubkeyPath: SSM_PATH }),
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
    const credential = `${claims.keyId}.${makeToken(claims)}`;
    await verifyMerchantToken(credential, { ssmPubkeyPath: SSM_PATH });
    await verifyMerchantToken(credential, { ssmPubkeyPath: SSM_PATH });
    expect(mockSsmSend).toHaveBeenCalledTimes(1);
  });
});
