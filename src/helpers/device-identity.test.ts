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

/**
 * Mint a pubkey + sig over a caller-supplied signed-input buffer.
 * Returns the pubkey too so tests can swap pubkeys vs sigs to exercise
 * negative paths.
 */
async function mintIdentitySigning(signedInput: Uint8Array): Promise<{
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
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    webPriv,
    signedInput,
  );
  return { pubkeyB64, sigB64: Buffer.from(sig).toString("base64") };
}

/** Mint via the legacy v1 XOR construction. */
async function mintIdentity(h2Token: string): Promise<{
  pubkeyB64: string;
  sigB64: string;
}> {
  const tokenBytes = new TextEncoder().encode(h2Token);
  return mintIdentitySigning(xor(tokenBytes, XOR_KEY));
}

/** Mint via the v2 payload-binding construction. */
async function mintIdentityV2(
  h2Token: string,
  stableHash: string,
  fuzzyHash: string,
): Promise<{ pubkeyB64: string; sigB64: string }> {
  const canonical = `${h2Token}|${stableHash}|${fuzzyHash}`;
  return mintIdentitySigning(new TextEncoder().encode(canonical));
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

  it("verifies a well-formed sig + pubkey + token (v1 legacy XOR)", async () => {
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

  // ── v2 (payload-binding) coverage — ARGUS_URGENT_FIXES #5 hardening ────

  it("verifies a v2 sig over (h2Token || stableHash || fuzzyHash)", async () => {
    const token = "v2tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentityV2(
      token,
      "stable-a",
      "fuzzy-a",
    );
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "stable-a", fuzzy: "fuzzy-a" },
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toMatchObject({ present: true, verified: true });
  });

  it("v2 sig REJECTED when replayed against a payload with different hashes", async () => {
    // The headline of finding #5's hardening: a sig minted for one
    // payload must NOT verify against a different payload's hashes.
    // Pre-hardening (v1 only) this verified because the sig was just
    // over xor(h2Token, KEY) — independent of payload content.
    const token = "v2tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentityV2(
      token,
      "stable-a",
      "fuzzy-a",
    );

    // Same (pubkey, sig), but the payload claims DIFFERENT hashes:
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "stable-b", fuzzy: "fuzzy-b" }, // ← different
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toMatchObject({ verified: false, reason: "sig_invalid" });
  });

  it("v2 sig REJECTED when stableHash differs (fuzzy still matches)", async () => {
    const token = "v2tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentityV2(
      token,
      "stable-a",
      "fuzzy-a",
    );
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "stable-DIFFERENT", fuzzy: "fuzzy-a" },
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toMatchObject({ verified: false, reason: "sig_invalid" });
  });

  it("v2 sig REJECTED when fuzzyHash differs (stable still matches)", async () => {
    const token = "v2tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentityV2(
      token,
      "stable-a",
      "fuzzy-a",
    );
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "stable-a", fuzzy: "fuzzy-DIFFERENT" },
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toMatchObject({ verified: false, reason: "sig_invalid" });
  });

  it("v1 sigs still verify during SDK rollout (backward compat)", async () => {
    // Legacy SDK bundles still signing the v1 XOR construction must
    // continue to land verified=true until they're rolled to v2.
    const token = "v1tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentity(token);
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "anything", fuzzy: "anything-else" },
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome).toMatchObject({ verified: true });
  });

  it("v1 sig replay across payloads still verifies (known gap during rollout)", async () => {
    // The v1 fallback is intentionally permissive — it's the same shape
    // as today's behavior, kept ONLY so legacy SDK bundles continue
    // working. This test documents the gap: once the SDK rolls and we
    // remove the v1 fallback, this test should flip to expect
    // verified=false.
    const token = "v1tok.99999999.deadbeef";
    const { pubkeyB64, sigB64 } = await mintIdentity(token);
    // Same sig, totally different payload — v1 doesn't bind to hashes:
    const outcome = await verifyDeviceIdentity(
      basePayload({
        hashes: { stable: "different", fuzzy: "different" },
        device_identity: { pubkey: pubkeyB64, sig: sigB64 },
        sigintH2Token: token,
      }),
    );
    expect(outcome.verified).toBe(true);
  });
});
