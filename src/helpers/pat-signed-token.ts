/**
 * Self-contained signed PAT-attestation token.
 *
 * Replaces the previous DB-backed `{nonce}.{expiry}.{hmac}` flow: the PAT
 * Lambda packs all the signal we want to surface (`type`, `issuer`,
 * `attested`, `src_ip`, `cpi`, `session_id`, `iat`, `exp`, `token_hash`) into a JSON payload,
 * base64url-encodes it, and HMACs it with the SIGINT_AES_KEY. The
 * ingestion Lambda verifies the HMAC, validates freshness and the exact scan binding,
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

/** Default freshness window from issue to expiry — server-side enforced
 *  (verifyPatAttestation rejects past this). Security boundary. */
export const DEFAULT_TTL_MS = 60_000;

/** Compatibility field retained in the response contract. The SDK does not
 * cache attestations because each one is bound to a single scan session. */
export const CLIENT_REFRESH_SECONDS = 45;

/** Inputs the PAT Lambda has after a successful PAT verify. */
export interface SignPatInput {
  issuer: string;
  /** Source IP observed at the PAT Lambda; binds the token to that network path. */
  srcIp: string;
  /** Public merchant partition this proof may accompany. */
  cpi: string;
  /** Exact Argus integrity session this proof may accompany. */
  sessionId: string;
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
  cpi: string;
  session_id: string;
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
  | "WRONG_IP"
  | "WRONG_CPI"
  | "WRONG_SESSION";

export interface ExpectedPatBinding {
  srcIp: string;
  cpi: string;
  sessionId: string;
}

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
    cpi: input.cpi,
    session_id: input.sessionId,
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
 * @param expected       the request's server-observed scan binding
 * @param sigintAesKeyHex first 32 bytes of SIGINT_AES_KEY, hex-encoded
 * @param nowMs         clock for freshness check (default Date.now())
 */
export function verifyPatAttestation(
  token: string,
  expected: ExpectedPatBinding,
  sigintAesKeyHex: string,
  nowMs: number = Date.now(),
): VerifyResult {
  const sep = token.lastIndexOf(".");
  if (sep <= 0 || sep === token.length - 1) {
    return { ok: false, reason: "MALFORMED" };
  }
  const b64 = token.slice(0, sep);
  const mac = token.slice(sep + 1);

  const expectedMac = createHmac("sha256", hmacKey(sigintAesKeyHex))
    .update(b64)
    .digest("hex");
  if (!ctEqHex(expectedMac, mac)) {
    return { ok: false, reason: "BAD_HMAC" };
  }

  const payload = decodePayload(b64);
  if (!payload) return { ok: false, reason: "BAD_PAYLOAD" };

  const failure = validatePayload(payload, expected, nowMs);
  if (failure) return { ok: false, reason: failure };

  return { ok: true, payload };
}

function decodePayload(encoded: string): SignedPatPayload | null {
  try {
    const parsed = JSON.parse(
      b64urlDecode(encoded).toString("utf8"),
    ) as unknown;
    return isSignedPatPayload(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function validatePayload(
  payload: SignedPatPayload,
  expected: ExpectedPatBinding,
  nowMs: number,
): VerifyFailureReason | null {
  if (payload.type !== TYPE || payload.attested !== true) return "WRONG_TYPE";
  if (Math.floor(nowMs / 1000) > payload.exp) return "EXPIRED";
  if (payload.src_ip !== expected.srcIp) return "WRONG_IP";
  if (payload.cpi !== expected.cpi) return "WRONG_CPI";
  if (payload.session_id !== expected.sessionId) return "WRONG_SESSION";
  return null;
}

function isSignedPatPayload(x: unknown): x is SignedPatPayload {
  if (!x || typeof x !== "object") return false;
  const r = x as Record<string, unknown>;
  const stringFields = ["issuer", "src_ip", "cpi", "session_id", "token_hash"];
  const numberFields = ["iat", "exp"];
  return (
    r.v === VERSION &&
    r.type === TYPE &&
    r.attested === true &&
    stringFields.every((field) => typeof r[field] === "string") &&
    numberFields.every((field) => typeof r[field] === "number")
  );
}
