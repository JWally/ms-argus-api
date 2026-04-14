import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { verifyDeviceIdentity } from "./device-identity";
import type { ArgusPayload } from "./payload-schema";

// Same 16-byte constant as device-identity.ts. Duplicated here so the test
// stays independent of the helper's internals — if someone changes the key
// without updating both sides, these tests break loudly.
const XOR_KEY = new Uint8Array([
  0x5a, 0x3f, 0x91, 0x2c, 0xb7, 0x44, 0x68, 0xe1, 0xd0, 0x0a, 0x7d, 0x59, 0x13,
  0xee, 0x82, 0xbc,
]);

function xor(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}

/** Mint a pubkey + valid sig over an XOR'd h2 token, for happy-path tests. */
async function mintIdentity(h2Token: string): Promise<{
  pubkeyB64: string;
  sigB64: string;
}> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const pubkeySpki = publicKey.export({ format: "der", type: "spki" });
  const pubkeyB64 = Buffer.from(pubkeySpki).toString("base64");

  // Sign via Web Crypto to match the client and produce IEEE P1363 (raw r||s).
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  const webPriv = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const tokenBytes = new TextEncoder().encode(h2Token);
  const signedInput = xor(tokenBytes, XOR_KEY);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    webPriv,
    signedInput,
  );
  return { pubkeyB64, sigB64: Buffer.from(sig).toString("base64") };
}

function basePayload(extras: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    identifiers: { session_id: "s-1" },
    hashes: { stable: "abc", fuzzy: "def" },
    device: {},
    ...extras,
  };
}

describe("verifyDeviceIdentity", () => {
  it("returns absent when device_identity is missing", async () => {
    const outcome = await verifyDeviceIdentity(basePayload());
    expect(outcome).toEqual({
      present: false,
      verified: false,
      pubkey: null,
      sig_present: false,
      reason: "absent",
    });
  });

  it("returns malformed when device_identity lacks pubkey", async () => {
    const outcome = await verifyDeviceIdentity(
      basePayload({
        // @ts-expect-error intentional: exercise bad input
        device_identity: { sig: "aGVsbG8=" },
        sigintH2Token: "tok",
      }),
    );
    expect(outcome.verified).toBe(false);
    expect(outcome).toMatchObject({ reason: "malformed", sig_present: true });
  });

  it("returns malformed when sig is missing", async () => {
    const outcome = await verifyDeviceIdentity(
      basePayload({
        // @ts-expect-error intentional
        device_identity: { pubkey: "X" },
        sigintH2Token: "tok",
      }),
    );
    expect(outcome.verified).toBe(false);
    expect(outcome).toMatchObject({ reason: "malformed", sig_present: false });
  });

  it("returns probe_token_missing when no h2 token is in the payload", async () => {
    const { pubkeyB64, sigB64 } = await mintIdentity("any");
    const outcome = await verifyDeviceIdentity(
      basePayload({
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
      }),
    );
    expect(outcome.verified).toBe(false);
    expect(outcome).toMatchObject({ reason: "probe_token_missing" });
  });

  it("returns pubkey_invalid on garbage pubkey bytes", async () => {
    const outcome = await verifyDeviceIdentity(
      basePayload({
        device_identity: { pubkey: "not-real-base64-spki", sig: "aGVsbG8=" },
        sigintH2Token: "tok",
      }),
    );
    expect(outcome).toMatchObject({
      verified: false,
      reason: "pubkey_invalid",
    });
  });

  it("returns sig_invalid when sig is over the wrong bytes", async () => {
    const { pubkeyB64 } = await mintIdentity("intended-token");
    // Re-mint a sig over a *different* token using a fresh keypair — then
    // swap in the wrong pubkey. Or easier: use the right pubkey but supply a
    // sig over unrelated bytes.
    const { sigB64 } = await mintIdentity("different-token");
    const outcome = await verifyDeviceIdentity(
      basePayload({
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: "intended-token",
      }),
    );
    expect(outcome).toMatchObject({ verified: false, reason: "sig_invalid" });
  });

  it("verifies a well-formed sig + pubkey + token", async () => {
    const token = "abc123.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentity(token);
    const outcome = await verifyDeviceIdentity(
      basePayload({
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toEqual({
      present: true,
      verified: true,
      pubkey: pubkeyB64,
      sig_present: true,
    });
  });
});
