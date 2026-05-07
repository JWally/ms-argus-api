/**
 * Pure encoder for the TokenChallenge struct (RFC 9577 §2.1).
 *
 * Loose-coupling contract: zero I/O, no side effects. Inputs are JS values,
 * output is a Buffer. Deletable in isolation.
 *
 * struct {
 *   uint16 token_type;             // 0x0002 for RSA Blind Signatures
 *   uint16 issuer_name_length;
 *   char   issuer_name[];          // hostname iOS will route attestation to
 *   uint8  redemption_context_length;  // 0 (unbound) or 32 (bound to a session)
 *   uint8  redemption_context[];
 *   uint16 origin_info_length;
 *   char   origin_info[];          // origin hostname (or comma-separated list)
 * } TokenChallenge;
 */

const TOKEN_TYPE_RSA_BLIND = 0x0002;

export interface TokenChallengeInput {
  /** Issuer hostname iOS attester will route to (must be on Apple's allowlist). */
  issuerName: string;
  /**
   * Redemption context — a 32-byte nonce that binds the token to a specific
   * server-side context (e.g. a session). Use empty Buffer for unbound (cacheable)
   * tokens. iOS caches unbound tokens aggressively, so prefer bound for fresh
   * attestation per scan.
   */
  redemptionContext?: Buffer;
  /** Origin hostname (or comma-separated list). Defaults to empty (unspecified). */
  originInfo?: string;
}

/** Encode a TokenChallenge struct. Throws only on grossly invalid input lengths. */
export function encodeTokenChallenge(input: TokenChallengeInput): Buffer {
  const issuer = Buffer.from(input.issuerName, "utf8");
  const redemption = input.redemptionContext ?? Buffer.alloc(0);
  const origin = Buffer.from(input.originInfo ?? "", "utf8");

  if (issuer.length > 0xffff) throw new Error("issuer_name too long");
  if (origin.length > 0xffff) throw new Error("origin_info too long");
  if (redemption.length !== 0 && redemption.length !== 32) {
    throw new Error("redemption_context must be 0 or 32 bytes");
  }

  const total =
    2 + 2 + issuer.length + 1 + redemption.length + 2 + origin.length;
  const out = Buffer.alloc(total);
  let off = 0;

  out.writeUInt16BE(TOKEN_TYPE_RSA_BLIND, off);
  off += 2;
  out.writeUInt16BE(issuer.length, off);
  off += 2;
  issuer.copy(out, off);
  off += issuer.length;
  out.writeUInt8(redemption.length, off);
  off += 1;
  redemption.copy(out, off);
  off += redemption.length;
  out.writeUInt16BE(origin.length, off);
  off += 2;
  origin.copy(out, off);

  return out;
}
