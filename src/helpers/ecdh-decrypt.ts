/**
 * ECDH + HKDF + AES-256-GCM decryption for argus-web encrypted payloads.
 *
 * Wire format (client → server):
 *   Content-Type: application/octet-stream
 *   X-Argus-Origin: <raw P-256 client public key, base64, 88 chars>
 *   Body: base64([iv(12 bytes) | AES-GCM ciphertext+tag])
 *
 * After decryption, the plaintext is pako deflateRaw-compressed JSON.
 * inflateRawSync decompresses it to an ArgusPayload JSON string.
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
 * Decrypt an ECDH-encrypted argus-web payload.
 *
 * @param body - Raw request body string (may be base64 if isBase64Encoded)
 * @param isBase64Encoded - Whether API Gateway base64-encoded the body
 * @param clientPubKey - Client raw P-256 public key from X-Argus-Origin header (base64)
 * @param keys - Server ECDH key pair (current + optional previous)
 * @returns Parsed JSON payload, or null if all decryption attempts fail
 */
export async function decryptArgusPayload(
  body: string,
  isBase64Encoded: boolean,
  clientPubKey: string,
  keys: EcdhKeys,
): Promise<unknown | null> {
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
        const inflated = inflateRawSync(Buffer.from(decrypted));
        return JSON.parse(inflated.toString("utf-8"));
      } catch {
        // try next key/date combo
      }
    }
  }

  return null;
}
