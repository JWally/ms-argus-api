/**
 * Pure RSA-PSS verifier for Apple Private Access Tokens (RFC 9578 type 0x0002).
 *
 * Loose-coupling contract: this module performs ZERO I/O. Inputs are bytes,
 * outputs are a result discriminated union. It can be deleted in isolation
 * if the issuer ecosystem disappears — no caller outside `pat-attest/`
 * imports it.
 *
 * RFC 9578 §6.1 token layout (token_type = 0x0002, RSA Blind Signatures):
 *   uint16 token_type            (2)
 *   uint8  nonce[32]             (32)
 *   uint8  challenge_digest[32]  (32)   = SHA256(TokenChallenge)
 *   uint8  token_key_id[32]      (32)   = SHA256(SPKI(token-key))
 *   uint8  authenticator[Nk]     (Nk)   RSASSA-PSS sig, Nk = key bytes (256 for 2048-bit RSA)
 *
 * RFC 9474 (Blind RSA): the unblinded `authenticator` is a standard RSASSA-PSS
 * signature using:
 *   - hash:        SHA-384
 *   - MGF:         MGF1 with SHA-384
 *   - salt length: 48
 * over the message `token_type || nonce || challenge_digest || token_key_id`.
 */

import { createHash, createPublicKey, verify, constants } from "crypto";

const TOKEN_TYPE_RSA_BLIND = 0x0002;
const NONCE_LEN = 32;
const DIGEST_LEN = 32;
const KEY_ID_LEN = 32;
const HEADER_LEN = 2 + NONCE_LEN + DIGEST_LEN + KEY_ID_LEN; // 98
const PSS_HASH = "sha384";
const PSS_SALT_LEN = 48;

export type VerifyFailureReason =
  | "MALFORMED_TOKEN"
  | "WRONG_TOKEN_TYPE"
  | "WRONG_CHALLENGE_DIGEST"
  | "WRONG_KEY_ID"
  | "BAD_SIGNATURE"
  | "BAD_KEY";

export type VerifyResult =
  | { ok: true; nonce: Buffer; tokenKeyId: Buffer }
  | { ok: false; reason: VerifyFailureReason };

interface ParsedToken {
  tokenType: number;
  nonce: Buffer;
  challengeDigest: Buffer;
  tokenKeyId: Buffer;
  authenticator: Buffer;
  signedMessage: Buffer; // first 98 bytes of the token, the RSA-PSS message
}

/** Parse a PAT type 0x0002 token. Returns null on any structural problem. */
function parsePatToken(tokenBytes: Buffer): ParsedToken | null {
  if (tokenBytes.length <= HEADER_LEN) return null;
  return {
    tokenType: tokenBytes.readUInt16BE(0),
    nonce: tokenBytes.subarray(2, 2 + NONCE_LEN),
    challengeDigest: tokenBytes.subarray(
      2 + NONCE_LEN,
      2 + NONCE_LEN + DIGEST_LEN,
    ),
    tokenKeyId: tokenBytes.subarray(
      2 + NONCE_LEN + DIGEST_LEN,
      2 + NONCE_LEN + DIGEST_LEN + KEY_ID_LEN,
    ),
    authenticator: tokenBytes.subarray(HEADER_LEN),
    signedMessage: tokenBytes.subarray(0, HEADER_LEN),
  };
}

/**
 * Extract the 32-byte challenge_digest (= SHA256(TokenChallenge)) from a PAT
 * token without verifying it. Used as the lookup key for the bound-challenge
 * store (#13) so a redeemed token can be matched to the exact challenge we
 * issued and consumed exactly once. Returns null on a structurally bad token.
 */
export function extractChallengeDigest(tokenBytes: Buffer): Buffer | null {
  const parsed = parsePatToken(tokenBytes);
  return parsed ? parsed.challengeDigest : null;
}

/** Constant-time equality on equal-length buffers. */
function ctEq(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verify a PAT against an expected challenge and an issuer SPKI public key.
 *
 * Inputs:
 *   tokenBytes        — raw bytes of the redeemed token (Authorization: PrivateToken token=base64url(tokenBytes))
 *   expectedChallenge — raw bytes of the TokenChallenge struct we issued
 *   tokenKeySpkiDer   — issuer's RSA public key in SubjectPublicKeyInfo DER form
 *
 * Returns a tagged result. NEVER throws.
 */
export function verifyPatToken(
  tokenBytes: Buffer,
  expectedChallenge: Buffer,
  tokenKeySpkiDer: Buffer,
): VerifyResult {
  const parsed = parsePatToken(tokenBytes);
  if (!parsed) return { ok: false, reason: "MALFORMED_TOKEN" };
  if (parsed.tokenType !== TOKEN_TYPE_RSA_BLIND) {
    return { ok: false, reason: "WRONG_TOKEN_TYPE" };
  }

  const expectedDigest = createHash("sha256")
    .update(expectedChallenge)
    .digest();
  if (!ctEq(parsed.challengeDigest, expectedDigest)) {
    return { ok: false, reason: "WRONG_CHALLENGE_DIGEST" };
  }

  const expectedKeyId = createHash("sha256").update(tokenKeySpkiDer).digest();
  if (!ctEq(parsed.tokenKeyId, expectedKeyId)) {
    return { ok: false, reason: "WRONG_KEY_ID" };
  }

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: tokenKeySpkiDer,
      format: "der",
      type: "spki",
    });
  } catch {
    return { ok: false, reason: "BAD_KEY" };
  }

  let valid: boolean;
  try {
    valid = verify(
      PSS_HASH,
      parsed.signedMessage,
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: PSS_SALT_LEN,
      },
      parsed.authenticator,
    );
  } catch {
    return { ok: false, reason: "BAD_SIGNATURE" };
  }

  if (!valid) return { ok: false, reason: "BAD_SIGNATURE" };

  return { ok: true, nonce: parsed.nonce, tokenKeyId: parsed.tokenKeyId };
}
