/**
 * ECDH + HKDF + AES-256-GCM decryption for argus-web encrypted payloads.
 *
 * Wire format (client → server):
 *   Content-Type: application/octet-stream
 *   X-Argus-Origin: <raw P-256 client public key, base64, 88 chars>
 *   Body: base64([iv(12 bytes) | AES-GCM ciphertext+tag])
 *
 * v1/v2 clients send pako deflateRaw-compressed plaintext. v3 clients
 * send the scrambled JSON bytes directly so the browser SDK does not need
 * to ship a deflate implementation.
 *
 * Key derivation:
 *   ECDH(serverPriv, clientPub) → 256-bit shared secret
 *   HKDF-SHA256(secret, salt=UTCdate, info="argus-web-v1") → AES-256-GCM key
 *
 * Tries current key + previous key × today + yesterday to handle:
 *   - Key rotation grace period
 *   - Midnight edge case (client and server in different UTC days)
 *
 * Note: HKDF info string is intentionally different from ms-argus-bio
 * ("argus-bio-v1") to prevent cross-system key confusion.
 */

import { inflateRawSync } from "zlib";
import type { EcdhKeys, EcdhKeyData } from "./get-ecdh-keys";

const HKDF_INFO = new TextEncoder().encode("argus-web-v1");

/**
 * v1 XOR-unscramble: repeating key = sessionToken + deploySecret.
 * Kept for backwards compatibility with clients that don't send X-Argus-V: 2.
 */
export function xorUnscramble(data: Buffer, key: string): Buffer {
  const keyBuf = Buffer.from(key, "utf-8");
  const result = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ keyBuf[i % keyBuf.length];
  }
  return result;
}

/**
 * v2 Fibonacci-modulated unscramble using sessionToken as sole seed.
 *
 * The client VM XORs the JSON **string** char-by-char before TextEncoder.encode
 * converts it to UTF-8. We must reverse this at the string level, not byte level,
 * because XOR'd characters > 127 become multi-byte in UTF-8.
 *
 * Flow: inflate → decode UTF-8 to string → XOR chars → encode back to UTF-8 bytes.
 * Fibonacci resets at 1M to match the client's integer overflow prevention.
 */
export function deriveAndUnscramble(
  data: Buffer,
  sessionToken: string,
): Buffer {
  const str = data.toString("utf-8");
  let result = "";
  let fib0 = 1;
  let fib1 = 1;
  for (let i = 0; i < str.length; i++) {
    const t = sessionToken.charCodeAt(i % sessionToken.length);
    const f = fib1 % 256;
    result += String.fromCharCode(str.charCodeAt(i) ^ (t ^ f));
    const fib2 = fib0 + fib1;
    fib0 = fib1;
    fib1 = fib2;
    if (fib1 > 1000000) {
      fib0 = 1;
      fib1 = 1;
    }
  }
  return Buffer.from(result, "utf-8");
}

async function deriveAesKey(
  serverPrivKeyPkcs8: string,
  clientPubKeyRaw: string,
  dateSalt: string,
): Promise<CryptoKey> {
  const privBytes = Buffer.from(serverPrivKeyPkcs8, "base64");
  const serverPrivKey = await crypto.subtle.importKey(
    "pkcs8",
    privBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

  const pubBytes = Buffer.from(clientPubKeyRaw, "base64");
  const clientPubKey = await crypto.subtle.importKey(
    "raw",
    pubBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPubKey },
    serverPrivKey,
    256,
  );

  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"],
  );
  const salt = new TextEncoder().encode(dateSalt);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

/**
 * Hard cap on inflated plaintext size (zip-bomb defense).
 *
 * The /v1/integrity-collect endpoint is sealed to the ECDH path only (see
 * middleware.enforceIntegrityCollectSeal), so this inflate — NOT the gzip
 * path's streamingGunzip — is where an attacker-supplied deflate bomb lands.
 * deriveAesKey accepts any X-Argus-Origin pubkey against the server key, so
 * the decrypt itself is not an auth gate; the bound is what stops a validly
 * encrypted 10MB body from expanding to hundreds of MB of heap. Mirrors the
 * gzip path's maxDecompressedBytes. Overflow throws RangeError, which the
 * per-key try/catch below already handles (falls through → null → HTTP 400).
 */
const MAX_INFLATED_BYTES = Number(
  process.env.MAX_DECOMPRESSED_BYTES ?? 2 * 1024 * 1024,
);

/** Bounded inflate — see MAX_INFLATED_BYTES. */
function boundedInflate(b: Buffer): Buffer {
  return inflateRawSync(b, { maxOutputLength: MAX_INFLATED_BYTES });
}

/**
 * Reverses the client's post-ECDH-encryption transform (inflate and/or
 * unscramble). Called INSIDE the per-key try/catch so a malformed unwrap on
 * the wrong key/date falls through to the next combo, exactly as before.
 */
type Unwrap = (plaintext: Buffer) => Buffer;

/** Transport inputs common to every ECDH decrypt variant. */
interface EcdhDecryptInput {
  body: string;
  isBase64Encoded: boolean;
  clientPubKey: string;
  keys: EcdhKeys;
}

/**
 * Core ECDH + AES-256-GCM decrypt with the standard current/previous ×
 * today/yesterday key-trial loop. The per-version behavior (inflate, XOR
 * unscramble, Fibonacci unscramble, or none) is supplied as `unwrap`.
 *
 * IMPORTANT: this is the shared implementation only. Version SELECTION stays
 * in middleware (X-Argus-V switch) — do NOT collapse the four exported
 * adapters into "try every unwrap until one parses", which would let a client
 * downgrade to the weaker v1 XOR path.
 */
async function decryptEcdh(
  input: EcdhDecryptInput,
  unwrap: Unwrap,
): Promise<unknown | null> {
  const { body, isBase64Encoded, clientPubKey, keys } = input;
  const packed = isBase64Encoded
    ? Buffer.from(body, "base64")
    : Buffer.from(body, "binary");

  const iv = packed.subarray(0, 12);
  const ciphertextWithTag = packed.subarray(12);

  const keySets = [keys.current, keys.previous].filter(
    (k): k is EcdhKeyData => k != null,
  );
  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86_400_000)
    .toISOString()
    .slice(0, 10);

  for (const keySet of keySets) {
    for (const dateSalt of [today, yesterday]) {
      try {
        const aesKey = await deriveAesKey(
          keySet.privateKey,
          clientPubKey,
          dateSalt,
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          aesKey,
          ciphertextWithTag,
        );
        return JSON.parse(unwrap(Buffer.from(decrypted)).toString("utf-8"));
      } catch {
        // wrong key/date, malformed unwrap, or oversized inflate → next combo
      }
    }
  }

  return null;
}

/**
 * Decrypt an ECDH-encrypted argus-web payload.
 *
 * @param body - Raw request body string (may be base64 if isBase64Encoded)
 * @param isBase64Encoded - Whether API Gateway base64-encoded the body
 * @param clientPubKey - Client raw P-256 public key from X-Argus-Origin header (base64)
 * @param keys - Server ECDH key pair (current + optional previous)
 * @returns Parsed JSON payload, or null if all decryption attempts fail
 */
export function decryptArgusPayload(
  body: string,
  isBase64Encoded: boolean,
  clientPubKey: string,
  keys: EcdhKeys,
): Promise<unknown | null> {
  return decryptEcdh(
    { body, isBase64Encoded, clientPubKey, keys },
    boundedInflate,
  );
}

export interface IntegrityDecryptOpts {
  body: string;
  isBase64Encoded: boolean;
  clientPubKey: string;
  keys: EcdhKeys;
  innerKey: string;
}

/**
 * Decrypt an ECDH-encrypted integrity payload with inner XOR unscramble.
 *
 * Same as decryptArgusPayload but after ECDH decrypt + inflate, applies
 * XOR unscramble with (h2Token + deploySecret) before JSON parsing.
 * The inner scramble runs inside the client's VM bytecode, so an attacker
 * intercepting the ECDH bridge call sees garbage instead of plaintext JSON.
 */
export function decryptIntegrityPayload(
  opts: IntegrityDecryptOpts,
): Promise<unknown | null> {
  const { body, isBase64Encoded, clientPubKey, keys, innerKey } = opts;
  return decryptEcdh({ body, isBase64Encoded, clientPubKey, keys }, (b) =>
    xorUnscramble(boundedInflate(b), innerKey),
  );
}

export interface IntegrityDecryptV2Opts {
  body: string;
  isBase64Encoded: boolean;
  clientPubKey: string;
  keys: EcdhKeys;
  sessionToken: string;
}

/**
 * v2: Decrypt integrity payload with Fibonacci-modulated sessionToken derivation.
 *
 * Same ECDH decrypt + inflate as v1, but the inner unscramble uses
 * deriveAndUnscramble(sessionToken) instead of xorUnscramble(sessionToken + deploySecret).
 * No static secret required — the algorithm is the secret.
 */
export function decryptIntegrityPayloadV2(
  opts: IntegrityDecryptV2Opts,
): Promise<unknown | null> {
  const { body, isBase64Encoded, clientPubKey, keys, sessionToken } = opts;
  return decryptEcdh({ body, isBase64Encoded, clientPubKey, keys }, (b) =>
    deriveAndUnscramble(boundedInflate(b), sessionToken),
  );
}

/**
 * v3: Decrypt integrity payload without transport compression.
 *
 * The VM still Fibonacci-scrambles the JSON string before ECDH encryption,
 * but the browser sends those UTF-8 bytes directly instead of pako
 * deflateRaw-compressing them. This keeps v1/v2 compatibility while letting
 * the SDK drop the pako dependency.
 */
export function decryptIntegrityPayloadV3(
  opts: IntegrityDecryptV2Opts,
): Promise<unknown | null> {
  const { body, isBase64Encoded, clientPubKey, keys, sessionToken } = opts;
  return decryptEcdh({ body, isBase64Encoded, clientPubKey, keys }, (b) =>
    deriveAndUnscramble(Buffer.from(b), sessionToken),
  );
}
