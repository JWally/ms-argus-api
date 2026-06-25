import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifySdkAttestation, type SdkAttestation } from "./sdk-attestation";

const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
const publicKeyB64 = publicKeyDer.toString("base64");
const keyId = createHash("sha256")
  .update(publicKeyDer)
  .digest("hex")
  .slice(0, 16);

function base64url(bytes: Buffer): string {
  return bytes
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function makeAttestation(
  envelopeOverrides: Record<string, unknown> = {},
): SdkAttestation {
  const now = Math.floor(Date.now() / 1000);
  const envelope = {
    v: 1,
    purpose: "argus-session-get-v1",
    payload: {
      cpi: "argus_cpi_test_abc1234567890",
      sessionId: "sid-1",
      checkoutNonce: "checkout-123",
    },
    iat: now - 1,
    exp: now + 60,
    keyId,
    ...envelopeOverrides,
  };
  const envelopeBytes = Buffer.from(JSON.stringify(envelope));
  const encodedEnvelope = base64url(envelopeBytes);
  return {
    envelope: encodedEnvelope,
    signature: sign("sha256", Buffer.from(encodedEnvelope), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64"),
    publicKey: publicKeyB64,
    keyId,
  };
}

describe("verifySdkAttestation", () => {
  it("accepts a signed SDK envelope bound to the requested cpi and session", () => {
    const result = verifySdkAttestation(makeAttestation(), {
      expectedPurpose: "argus-session-get-v1",
      expectedCpi: "argus_cpi_test_abc1234567890",
      expectedSessionId: "sid-1",
    });

    expect(result).toMatchObject({
      ok: true,
      keyId,
      payload: {
        cpi: "argus_cpi_test_abc1234567890",
        sessionId: "sid-1",
        checkoutNonce: "checkout-123",
      },
    });
  });

  it("rejects an envelope signed for a different session", () => {
    const result = verifySdkAttestation(makeAttestation(), {
      expectedPurpose: "argus-session-get-v1",
      expectedCpi: "argus_cpi_test_abc1234567890",
      expectedSessionId: "sid-2",
    });

    expect(result).toEqual({ ok: false, reason: "session_mismatch" });
  });

  it("rejects a tampered signature", () => {
    const att = makeAttestation();
    const result = verifySdkAttestation(
      { ...att, signature: Buffer.from("nope").toString("base64") },
      {
        expectedPurpose: "argus-session-get-v1",
        expectedCpi: "argus_cpi_test_abc1234567890",
        expectedSessionId: "sid-1",
      },
    );

    expect(result).toEqual({ ok: false, reason: "bad_signature" });
  });
});
