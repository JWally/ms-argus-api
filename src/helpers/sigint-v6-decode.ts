/**
 * TypeScript port of src-go/stun/cipher/v6payload.go (Decode path only).
 *
 * The argus sigint STUN server encodes the client's observed IPv4 into the
 * 16-byte IPv6 field of XOR-MAPPED-ADDRESS:
 *
 *   byte  0..3  : clientIPv4          (big-endian)
 *   byte  4..7  : epoch seconds       (big-endian)
 *   byte  8..11 : random nonce
 *   byte 12..15 : HMAC-SHA256 tag     (truncated to 4 bytes over bytes 0..11)
 *
 * The whole block is AES-128 encrypted as a single ECB block (equivalent to
 * CBC with IV=0 at exactly one block). Keys come from HKDF-SHA256 of the
 * shared 32-byte secret.
 */

import {
  createDecipheriv,
  createHmac,
  hkdfSync,
  timingSafeEqual,
} from "crypto";

const V6_PAYLOAD_SIZE = 16;
const HKDF_INFO = "argus-sigint-v6-payload-v1";
const FRESH_WINDOW_SECONDS = 300;

export interface DecodedV6Payload {
  ip: string;
  epoch: number;
  ageSec: number;
  nonce: string;
  macValid: boolean;
  fresh: boolean;
}

interface DerivedKeys {
  encKey: Buffer;
  macKey: Buffer;
}

function deriveKeys(secretHex: string): DerivedKeys | null {
  let secret: Buffer;
  try {
    secret = Buffer.from(secretHex, "hex");
  } catch {
    return null;
  }
  if (secret.length !== 32) return null;
  // HKDF with nil salt → RFC 5869 substitutes HashLen zero bytes. Node's
  // hkdfSync requires a salt arg; empty Buffer produces the same output as
  // a zero-filled 32-byte salt (matches Go's x/crypto/hkdf behaviour).
  const okm = Buffer.from(
    hkdfSync("sha256", secret, Buffer.alloc(0), HKDF_INFO, 48),
  );
  return { encKey: okm.subarray(0, 16), macKey: okm.subarray(16, 48) };
}

function aes128EcbDecryptBlock(ciphertext: Buffer, encKey: Buffer): Buffer {
  const decipher = createDecipheriv("aes-128-ecb", encKey, null);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function verifyTag(plain: Buffer, macKey: Buffer): boolean {
  const expected = createHmac("sha256", macKey)
    .update(plain.subarray(0, 12))
    .digest()
    .subarray(0, 4);
  const actual = plain.subarray(12, 16);
  try {
    return timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/**
 * Decode a 16-byte ciphertext produced by the sigint STUN server.
 * Returns null when the input is malformed or the key can't be derived.
 * `macValid` / `fresh` flags let callers decide whether to trust the payload.
 */
export function decodeV6Payload(
  ciphertext: Buffer,
  secretHex: string,
  now: Date = new Date(),
): DecodedV6Payload | null {
  if (ciphertext.length !== V6_PAYLOAD_SIZE) return null;
  const keys = deriveKeys(secretHex);
  if (!keys) return null;

  const plain = aes128EcbDecryptBlock(ciphertext, keys.encKey);
  const macValid = verifyTag(plain, keys.macKey);

  const ip = `${plain[0]}.${plain[1]}.${plain[2]}.${plain[3]}`;
  const epoch = plain.readUInt32BE(4);
  const nonce = plain.subarray(8, 12).toString("hex");
  const ageSec = Math.floor(now.getTime() / 1000) - epoch;

  return {
    ip,
    epoch,
    ageSec,
    nonce,
    macValid,
    fresh: macValid && Math.abs(ageSec) <= FRESH_WINDOW_SECONDS,
  };
}

function expandIpv6Hextets(addr: string): string[] | null {
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  if (halves.length === 1) return left.length === 8 ? left : null;
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  return [...left, ...new Array(missing).fill("0"), ...right];
}

function hextetsToBytes(hextets: string[]): Buffer | null {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(hextets[i])) return null;
    out.writeUInt16BE(parseInt(hextets[i], 16), i * 2);
  }
  return out;
}

/**
 * Parse an IPv6 address string into 16 raw bytes.
 * Accepts `::` shorthand and full 8-hextet form. Returns null on parse failure.
 * Does not support IPv4-mapped suffixes (`::ffff:1.2.3.4`) — the sigint STUN
 * never emits that shape.
 */
export function ipv6StringToBytes(addr: string): Buffer | null {
  if (typeof addr !== "string" || addr.length === 0) return null;
  const hextets = expandIpv6Hextets(addr);
  if (!hextets || hextets.length !== 8) return null;
  return hextetsToBytes(hextets);
}

export interface SigintCandidateDecodeResult {
  /** Decoded payload from the single valid srflx candidate, if any. */
  decoded: DecodedV6Payload | null;
  /** Candidates seen on the wire (for diagnostics, even when we skip them). */
  candidateCount: number;
  /**
   * Why the result may be null despite candidates being present.
   * "no_candidates" | "multi_candidates" | "parse_fail" | "decode_fail"
   */
  reason:
    | "ok"
    | "no_candidates"
    | "multi_candidates"
    | "parse_fail"
    | "decode_fail";
}

interface RawSigintCandidate {
  address?: unknown;
  port?: unknown;
}

function extractSigintCandidates(device: unknown): RawSigintCandidate[] | null {
  if (!device || typeof device !== "object") return null;
  const webrtc = (device as { webrtc?: unknown }).webrtc;
  if (!webrtc || typeof webrtc !== "object") return null;
  const ice = (webrtc as { iceCandidates?: unknown }).iceCandidates;
  if (!ice || typeof ice !== "object") return null;
  const raw = (ice as { sigintCandidates?: unknown }).sigintCandidates;
  if (!Array.isArray(raw)) return null;
  return raw as RawSigintCandidate[];
}

/**
 * Decode the sigint STUN srflx candidate(s) embedded in a device fingerprint.
 *
 * Policy: exactly one candidate is expected for single-homed clients. Zero or
 * multiple candidates short-circuit to null — multi = multi-egress (dual-stack
 * / VPN) and needs separate handling downstream, not silent picking.
 */
export function decodeWebrtcSigintCandidates(
  device: unknown,
  secretHex: string | undefined,
  now: Date = new Date(),
): SigintCandidateDecodeResult {
  const candidates = extractSigintCandidates(device) ?? [];
  if (!secretHex) {
    return {
      decoded: null,
      candidateCount: candidates.length,
      reason: "decode_fail",
    };
  }
  if (candidates.length === 0) {
    return { decoded: null, candidateCount: 0, reason: "no_candidates" };
  }
  if (candidates.length > 1) {
    return {
      decoded: null,
      candidateCount: candidates.length,
      reason: "multi_candidates",
    };
  }

  const { address } = candidates[0];
  if (typeof address !== "string") {
    return { decoded: null, candidateCount: 1, reason: "parse_fail" };
  }
  const bytes = ipv6StringToBytes(address);
  if (!bytes) {
    return { decoded: null, candidateCount: 1, reason: "parse_fail" };
  }
  const decoded = decodeV6Payload(bytes, secretHex, now);
  if (!decoded) {
    return { decoded: null, candidateCount: 1, reason: "decode_fail" };
  }
  return { decoded, candidateCount: 1, reason: "ok" };
}

/**
 * Build the `analysis.webrtc_sigint` field stored on integrity rows.
 * Returns undefined when no candidates were emitted, so the column stays
 * absent rather than being a noisy `{status: "no_candidates", ...}` stub.
 */
export function buildWebrtcSigintField(
  result: SigintCandidateDecodeResult,
): Record<string, unknown> | undefined {
  if (result.reason === "no_candidates") return undefined;
  const base: Record<string, unknown> = {
    status: result.reason,
    candidate_count: result.candidateCount,
  };
  if (result.decoded) {
    base.ip = result.decoded.ip;
    base.epoch = result.decoded.epoch;
    base.age_sec = result.decoded.ageSec;
    base.nonce = result.decoded.nonce;
    base.mac_valid = result.decoded.macValid;
    base.fresh = result.decoded.fresh;
  }
  return base;
}
