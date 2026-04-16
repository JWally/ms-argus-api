/**
 * Verify CloudFront TLS fingerprint token integrity.
 *
 * The CF edge function signs the payload with SipHash-2-4 over the canonical
 * string `id|issuedAt|ip|asn|ts` using the first 16 bytes of the stored 32-byte
 * hex key (same key as sigint probes — sourced from Secrets Manager). The
 * client must forward the signature alongside the parsed payload.
 *
 * Returns two boolean signals suitable for downstream analysis:
 *   - expired: `ts` is outside the ±90s freshness window
 *   - tampered: signature mismatch, missing sig, or missing required fields
 *
 * Both default to `true` (fail-closed) when verification cannot be performed.
 */

export interface CfTokenFields {
  id?: string;
  issuedAt?: number;
  ip?: string | null;
  asn?: string | null;
  ts?: number;
  sig?: string;
}

export interface CfTokenVerification {
  expired: boolean;
  tampered: boolean;
}

const MASK = 0xffffffffffffffffn;

function rotl(x: bigint, b: bigint): bigint {
  return ((x << b) | (x >> (64n - b))) & MASK;
}

/**
 * SipHash-2-4 with a 128-bit key producing a 64-bit (16 hex char) tag.
 * Matches the inline implementation in the CloudFront Function byte-for-byte:
 *   - 16-byte key from first 32 hex chars
 *   - UTF-8 message encoding
 *   - Pad message to multiple of 8 bytes; last byte of final block is `len & 0xff`
 *   - 2 compression rounds per block, 4 finalization rounds
 *   - Little-endian hex output
 */
export function sipHash24(keyHex: string, msg: string): string {
  if (keyHex.length < 32) throw new Error("SipHash key must be >=32 hex chars");
  const key = Buffer.from(keyHex.slice(0, 32), "hex");
  if (key.length !== 16) throw new Error("SipHash key must decode to 16 bytes");

  const k0 = key.readBigUInt64LE(0);
  const k1 = key.readBigUInt64LE(8);

  let v0 = (k0 ^ 0x736f6d6570736575n) & MASK;
  let v1 = (k1 ^ 0x646f72616e646f6dn) & MASK;
  let v2 = (k0 ^ 0x6c7967656e657261n) & MASK;
  let v3 = (k1 ^ 0x7465646279746573n) & MASK;

  const round = () => {
    v0 = (v0 + v1) & MASK;
    v1 = rotl(v1, 13n);
    v1 = (v1 ^ v0) & MASK;
    v0 = rotl(v0, 32n);
    v2 = (v2 + v3) & MASK;
    v3 = rotl(v3, 16n);
    v3 = (v3 ^ v2) & MASK;
    v0 = (v0 + v3) & MASK;
    v3 = rotl(v3, 21n);
    v3 = (v3 ^ v0) & MASK;
    v2 = (v2 + v1) & MASK;
    v1 = rotl(v1, 17n);
    v1 = (v1 ^ v2) & MASK;
    v2 = rotl(v2, 32n);
  };

  const msgBytes = Buffer.from(msg, "utf8");
  const ml = msgBytes.length;
  const totalLen = Math.floor(ml / 8) * 8 + 8;
  const padded = Buffer.alloc(totalLen);
  msgBytes.copy(padded, 0);
  padded[totalLen - 1] = ml & 0xff;

  for (let i = 0; i < totalLen; i += 8) {
    const m = padded.readBigUInt64LE(i);
    v3 = (v3 ^ m) & MASK;
    round();
    round();
    v0 = (v0 ^ m) & MASK;
  }

  v2 = (v2 ^ 0xffn) & MASK;
  round();
  round();
  round();
  round();

  const tag = (v0 ^ v1 ^ v2 ^ v3) & MASK;
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(tag, 0);
  return out.toString("hex");
}

function constantTimeStrEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verify a CloudFront TLS fingerprint payload.
 *
 * @param data - Parsed aws_cf payload (must contain sig to verify)
 * @param keyHex - SipHash key (hex, first 16 bytes used) — same key as sigint probes
 * @param now - Unix seconds for freshness check (defaults to Date.now())
 * @param maxAgeSeconds - Freshness window, default 90s matches API token policy
 */
export function verifyCfToken(
  data: CfTokenFields,
  keyHex: string,
  now: number = Math.floor(Date.now() / 1000),
  maxAgeSeconds = 90,
): CfTokenVerification {
  const result: CfTokenVerification = { expired: true, tampered: true };

  if (typeof data.ts === "number") {
    result.expired =
      now - data.ts > maxAgeSeconds || data.ts > now + maxAgeSeconds;
  }

  if (
    data.sig &&
    data.id &&
    typeof data.issuedAt === "number" &&
    typeof data.ts === "number"
  ) {
    const canonical = `${data.id}|${data.issuedAt}|${data.ip ?? ""}|${data.asn ?? ""}|${data.ts}`;
    const expected = sipHash24(keyHex, canonical);
    result.tampered = !constantTimeStrEq(expected, data.sig);
  }

  return result;
}

export interface CfCookieVerification {
  valid: boolean;
  id?: string;
  issuedAt?: number;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DIGITS_RE = /^\d+$/;

/**
 * Verify the _fpid cookie signature. Cookie format: `<uuid>_<issuedAt>.<sipSig>`
 * where sipSig = SipHash-2-4(key, "fpid|<uuid>|<issuedAt>").
 *
 * Returns valid=true with parsed fields when sig matches, valid=false otherwise.
 * CF trusts cookie contents without validation (instruction budget); this is
 * where we actually catch tamper attempts.
 */
export function verifyCfCookie(
  cookieValue: string,
  keyHex: string,
): CfCookieVerification {
  const dot = cookieValue.lastIndexOf(".");
  if (dot <= 0) return { valid: false };
  const body = cookieValue.substring(0, dot);
  const sig = cookieValue.substring(dot + 1);
  const sep = body.indexOf("_");
  if (sep <= 0) return { valid: false };
  const id = body.substring(0, sep);
  const tsStr = body.substring(sep + 1);
  if (!UUID_RE.test(id) || !DIGITS_RE.test(tsStr)) return { valid: false };
  const issuedAt = parseInt(tsStr, 10);
  const expected = sipHash24(keyHex, `fpid|${id}|${issuedAt}`);
  return {
    valid: constantTimeStrEq(expected, sig),
    id,
    issuedAt,
  };
}

/**
 * Extract the _fpid cookie value from an API Gateway V2 cookies array.
 * Returns the raw cookie value (uuid_ts.sig) without the `_fpid=` prefix.
 */
export function extractFpidCookie(cookies?: string[]): string | undefined {
  if (!cookies) return undefined;
  for (const raw of cookies) {
    // API Gateway V2 passes each cookie as its own array entry, but also
    // tolerate combined "a=1; b=2" form for safety.
    const parts = raw.split(";");
    for (const part of parts) {
      const t = part.trim();
      if (t.startsWith("_fpid=")) {
        return t.substring("_fpid=".length);
      }
    }
  }
  return undefined;
}
