/**
 * Self-contained signed PAT-attestation token.
 *
 * Replaces the previous DB-backed `{nonce}.{expiry}.{hmac}` flow: the PAT
 * Lambda packs all the signal we want to surface (`type`, `issuer`,
 * `attested`, `src_ip`, `iat`, `exp`, `token_hash`) into a JSON payload,
 * base64url-encodes it, and HMACs it with the SIGINT_AES_KEY. The
 * ingestion Lambda verifies the HMAC, validates freshness + IP binding,
 * and surfaces the contents on `payload.pat` — no DynamoDB round trip.
 *
 * Wire format (matches verify-cf-token's "self-contained signed string"
 * style; one `.` separator between the b64url payload and the hex MAC):
 *
 *   <base64url(JSON(SignedPatPayload))>.<hex(HMAC-SHA256(key, b64url))>
 *
 * Loose-coupling contract: pure functions, no I/O. Caller supplies the
 * key bytes; this module never touches Secrets Manager. Failure modes
 * return `null`, never throw.
 */

import { createHmac, timingSafeEqual } from "crypto";

const VERSION = 1;
const TYPE = "pat" as const;

/** Default freshness window from issue to expiry. */
export const DEFAULT_TTL_MS = 60_000;

/** Inputs the PAT Lambda has after a successful PAT verify. */
export interface SignPatInput {
  issuer: string;
  /** Source IP observed at the PAT Lambda; binds the token to that network path. */
  srcIp: string;
  /** SHA-256 hex of the raw PAT token bytes — preserves Apple's unlinkability. */
  tokenHash: string;
  /** First 32 bytes (decoded) of SIGINT_AES_KEY, hex-encoded. */
  sigintAesKeyHex: string;
  /** Override clock for tests. Defaults to Date.now(). */
  nowMs?: number;
  /** Override ttl for tests. Defaults to DEFAULT_TTL_MS. */
  ttlMs?: number;
}

/** Decoded payload (the JSON inside the b64url block). */
export interface SignedPatPayload {
  v: 1;
  type: "pat";
  issuer: string;
  attested: true;
  src_ip: string;
  iat: number; // epoch seconds
  exp: number; // epoch seconds
  token_hash: string;
}

export type VerifyFailureReason =
  | "MALFORMED"
  | "BAD_HMAC"
  | "BAD_PAYLOAD"
  | "WRONG_TYPE"
  | "EXPIRED"
  | "WRONG_IP";

export type VerifyResult =
  | { ok: true; payload: SignedPatPayload }
  | { ok: false; reason: VerifyFailureReason };

/** First 32 bytes of the hex key — same convention as redeem-sigint-tokens. */
function hmacKey(sigintAesKeyHex: string): Buffer {
  return Buffer.from(sigintAesKeyHex, "hex").subarray(0, 32);
}

function b64urlEncode(b: Buffer | string): string {
  const buf = typeof b === "string" ? Buffer.from(b, "utf8") : b;
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  return Buffer.from(
    s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad),
    "base64",
  );
}

function ctEqHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

export function signPatAttestation(input: SignPatInput): string {
  const nowMs = input.nowMs ?? Date.now();
  const ttlMs = input.ttlMs ?? DEFAULT_TTL_MS;
  const iat = Math.floor(nowMs / 1000);
  const exp = Math.floor((nowMs + ttlMs) / 1000);

  const payload: SignedPatPayload = {
    v: VERSION,
    type: TYPE,
    issuer: input.issuer,
    attested: true,
    src_ip: input.srcIp,
    iat,
    exp,
    token_hash: input.tokenHash,
  };

  const b64 = b64urlEncode(JSON.stringify(payload));
  const mac = createHmac("sha256", hmacKey(input.sigintAesKeyHex))
    .update(b64)
    .digest("hex");
  return `${b64}.${mac}`;
}

/**
 * Verify a signed PAT token. Returns the parsed payload on success.
 *
 * @param token         the `<b64url>.<hex>` string from `payload.patToken`
 * @param expectedSrcIp the request's TLS-observed source IP at ingestion
 * @param sigintAesKeyHex first 32 bytes of SIGINT_AES_KEY, hex-encoded
 * @param nowMs         clock for freshness check (default Date.now())
 */
export function verifyPatAttestation(
  token: string,
  expectedSrcIp: string,
  sigintAesKeyHex: string,
  nowMs: number = Date.now(),
): VerifyResult {
  const sep = token.lastIndexOf(".");
  if (sep <= 0 || sep === token.length - 1) {
    return { ok: false, reason: "MALFORMED" };
  }
  const b64 = token.slice(0, sep);
  const mac = token.slice(sep + 1);

  const expected = createHmac("sha256", hmacKey(sigintAesKeyHex))
    .update(b64)
    .digest("hex");
  if (!ctEqHex(expected, mac)) {
    return { ok: false, reason: "BAD_HMAC" };
  }

  let payload: SignedPatPayload;
  try {
    const parsed = JSON.parse(b64urlDecode(b64).toString("utf8")) as unknown;
    if (!isSignedPatPayload(parsed)) {
      return { ok: false, reason: "BAD_PAYLOAD" };
    }
    payload = parsed;
  } catch {
    return { ok: false, reason: "BAD_PAYLOAD" };
  }

  if (payload.type !== TYPE || payload.attested !== true) {
    return { ok: false, reason: "WRONG_TYPE" };
  }
  if (Math.floor(nowMs / 1000) > payload.exp) {
    return { ok: false, reason: "EXPIRED" };
  }
  if (payload.src_ip !== expectedSrcIp) {
    return { ok: false, reason: "WRONG_IP" };
  }

  return { ok: true, payload };
}

function isSignedPatPayload(x: unknown): x is SignedPatPayload {
  if (!x || typeof x !== "object") return false;
  const r = x as Record<string, unknown>;
  return (
    r.v === VERSION &&
    r.type === TYPE &&
    r.attested === true &&
    typeof r.issuer === "string" &&
    typeof r.src_ip === "string" &&
    typeof r.iat === "number" &&
    typeof r.exp === "number" &&
    typeof r.token_hash === "string"
  );
}
