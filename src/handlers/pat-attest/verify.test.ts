import { describe, it, expect, beforeAll } from "vitest";
import {
  createHash,
  generateKeyPairSync,
  sign as signRaw,
  constants,
  type KeyObject,
} from "crypto";
import { verifyPatToken } from "./verify";

/**
 * Build a synthetic PAT type-0x0002 token signed with a locally-generated
 * RSA-PSS key. Validates the verifier's signature path end-to-end. We do
 * NOT use real Fastly tokens here because (a) we'd need a live iPhone, and
 * (b) such tokens have short challenge bindings tied to a specific origin.
 */
interface SyntheticToken {
  tokenBytes: Buffer;
  challenge: Buffer;
  spkiDer: Buffer;
}

function buildSyntheticToken(
  privateKey: KeyObject,
  spkiDer: Buffer,
  challenge: Buffer,
): SyntheticToken {
  const tokenType = Buffer.alloc(2);
  tokenType.writeUInt16BE(0x0002);
  const nonce = Buffer.alloc(32, 0x11);
  const challengeDigest = createHash("sha256").update(challenge).digest();
  const tokenKeyId = createHash("sha256").update(spkiDer).digest();
  const signedMessage = Buffer.concat([
    tokenType,
    nonce,
    challengeDigest,
    tokenKeyId,
  ]);
  const authenticator = signRaw("sha384", signedMessage, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 48,
  });
  return {
    tokenBytes: Buffer.concat([signedMessage, authenticator]),
    challenge,
    spkiDer,
  };
}

describe("verifyPatToken", () => {
  let tok: SyntheticToken;
  let otherSpki: Buffer;

  beforeAll(() => {
    // Node 22 runtime accepts 'rsa-pss', but @types/node 22.7 hasn't
    // widened the union. Use an untyped wrapper so the runtime call goes
    // through verbatim — gives us the same RSASSA-PSS-keys SPKI shape
    // Fastly serves in production.
    const gen = generateKeyPairSync as unknown as (
      type: string,
      opts: object,
    ) => { publicKey: KeyObject; privateKey: KeyObject };
    const opts = {
      modulusLength: 2048,
      hashAlgorithm: "sha384",
      mgf1HashAlgorithm: "sha384",
      saltLength: 48,
    };
    const pair = gen("rsa-pss", opts);
    const spkiDer = pair.publicKey.export({
      format: "der",
      type: "spki",
    }) as Buffer;
    tok = buildSyntheticToken(
      pair.privateKey,
      spkiDer,
      Buffer.from("hello-challenge", "utf8"),
    );

    const other = gen("rsa-pss", opts);
    otherSpki = other.publicKey.export({
      format: "der",
      type: "spki",
    }) as Buffer;
  });

  it("accepts a well-formed token signed by the matching key", () => {
    const r = verifyPatToken(tok.tokenBytes, tok.challenge, tok.spkiDer);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.nonce.length).toBe(32);
      expect(r.tokenKeyId.length).toBe(32);
    }
  });

  it("rejects a token whose challenge differs from the expected", () => {
    const r = verifyPatToken(
      tok.tokenBytes,
      Buffer.from("different-challenge"),
      tok.spkiDer,
    );
    expect(r).toEqual({ ok: false, reason: "WRONG_CHALLENGE_DIGEST" });
  });

  it("rejects a token whose token_key_id matches a different SPKI", () => {
    const r = verifyPatToken(tok.tokenBytes, tok.challenge, otherSpki);
    expect(r).toEqual({ ok: false, reason: "WRONG_KEY_ID" });
  });

  it("rejects malformed (truncated) tokens", () => {
    const truncated = tok.tokenBytes.subarray(0, 50);
    const r = verifyPatToken(truncated, tok.challenge, tok.spkiDer);
    expect(r).toEqual({ ok: false, reason: "MALFORMED_TOKEN" });
  });

  it("rejects tokens with the wrong token_type", () => {
    const mutated = Buffer.from(tok.tokenBytes);
    mutated.writeUInt16BE(0x0001, 0);
    const r = verifyPatToken(mutated, tok.challenge, tok.spkiDer);
    expect(r).toEqual({ ok: false, reason: "WRONG_TOKEN_TYPE" });
  });

  it("rejects tokens whose authenticator is mutated", () => {
    const mutated = Buffer.from(tok.tokenBytes);
    mutated[mutated.length - 1] ^= 0x01; // flip a bit in the last byte
    const r = verifyPatToken(mutated, tok.challenge, tok.spkiDer);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("BAD_SIGNATURE");
  });
});
