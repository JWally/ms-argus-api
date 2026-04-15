/**
 * Device-identity verification helper.
 *
 * The client ships a persistent non-extractable ECDSA P-256 keypair (stored in
 * IndexedDB, generated on first visit). On every submission it sends:
 *
 *   payload.device_identity = { pubkey, sig }
 *
 * where `sig` is the ECDSA signature over `xor(sigintH2Token, KEY)`. Signing an
 * XOR'd server-issued token (instead of a plain timestamp) gives us:
 *   - Freshness: the h2-probe token has a 90s HMAC'd TTL
 *   - Unpredictability: attackers can't pre-compute sigs — token is server-chosen
 *   - Opacity: reversers hooking crypto.subtle.sign see XOR'd bytes, not an
 *     obviously-HMAC'd-token format
 *
 * The XOR key is NOT a secret. It's a cheap obfuscation layer to burn lazy
 * reversers; its value is inline on both sides.
 *
 * Failures are non-fatal — we record the outcome on the DDB row so it shows up
 * in analytics, but ingestion always succeeds.
 */

import type { ArgusPayload } from "./payload-schema";

/**
 * XOR obfuscation key shared between client (bytecode) and server. NOT a
 * secret — obfuscation only. If you change it here, change the matching
 * constant in `ms-argus-web-integrity/scripts/vm-src/main.ts` (and regenerate
 * the bytecode) or all client sigs will fail verification.
 */
const DEVICE_IDENTITY_XOR_KEY = new Uint8Array([
  0x5a, 0x3f, 0x91, 0x2c, 0xb7, 0x44, 0x68, 0xe1, 0xd0, 0x0a, 0x7d, 0x59, 0x13,
  0xee, 0x82, 0xbc,
]);

/** Repeating-key XOR. Output length matches input. */
function xorBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ key[i % key.length];
  }
  return out;
}

/** Reason codes surfaced on `identification.reason` when verification fails. */
export type IdentityFailReason =
  | "absent"
  | "probe_token_missing"
  | "malformed"
  | "pubkey_invalid"
  | "sig_invalid";

/** Result of `verifyDeviceIdentity` — always returns a value, never throws. */
export type IdentityOutcome =
  | { present: true; verified: true; pubkey: string; sig_present: true }
  | {
      present: true;
      verified: false;
      pubkey: string | null;
      sig_present: boolean;
      reason: IdentityFailReason;
    }
  | {
      present: false;
      verified: false;
      pubkey: null;
      sig_present: false;
      reason: "absent";
    };

/** Decode a base64 string into a Uint8Array. */
function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/**
 * Import an SPKI-base64 pubkey as an ECDSA P-256 verify key. Returns null on
 * any decode/import failure so callers can classify the result.
 */
async function importPubkey(spkiB64: string): Promise<CryptoKey | null> {
  try {
    const bytes = b64ToBytes(spkiB64);
    return await crypto.subtle.importKey(
      "spki",
      bytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
}

type Extracted =
  | { kind: "absent" }
  | { kind: "malformed"; pubkey: string | null; sig_present: boolean }
  | { kind: "no_probe_token"; pubkey: string }
  | { kind: "ok"; pubkey: string; sig: string; h2Token: string };

/**
 * Pull `pubkey`, `sig`, and `sigintH2Token` from the payload, classifying any
 * missing-or-malformed case. Keeps the verify function's branching linear.
 */
function extractIdentity(payload: ArgusPayload): Extracted {
  const identity = payload.device_identity;
  if (!identity || typeof identity !== "object") return { kind: "absent" };
  const { pubkey, sig } = identity;
  const sigPresent = typeof sig === "string" && sig.length > 0;
  const pubkeyValid = typeof pubkey === "string" && pubkey.length > 0;

  if (!pubkeyValid || !sigPresent) {
    return {
      kind: "malformed",
      pubkey: typeof pubkey === "string" ? pubkey : null,
      sig_present: sigPresent,
    };
  }

  const h2Token = payload.sigintH2Token;
  if (typeof h2Token !== "string" || h2Token.length === 0) {
    return { kind: "no_probe_token", pubkey };
  }
  return { kind: "ok", pubkey, sig, h2Token };
}

/**
 * Perform the actual ECDSA verify. Separate from the extraction path so the
 * top-level function stays flat.
 */
async function verifySignature(
  pubkeyB64: string,
  sigB64: string,
  h2Token: string,
): Promise<IdentityFailReason | null> {
  const key = await importPubkey(pubkeyB64);
  if (!key) return "pubkey_invalid";

  let sigBytes: Uint8Array;
  try {
    sigBytes = b64ToBytes(sigB64);
  } catch {
    return "malformed";
  }

  const signedInput = xorBytes(
    new TextEncoder().encode(h2Token),
    DEVICE_IDENTITY_XOR_KEY,
  );
  try {
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes,
      signedInput,
    );
    return ok ? null : "sig_invalid";
  } catch {
    return "sig_invalid";
  }
}

/**
 * Verify the client's device-identity signature against the h2-probe token.
 *
 * The caller must pass the raw (unhydrated) payload so we can read both
 * `device_identity` and `sigintH2Token` as they arrived on the wire.
 */
export async function verifyDeviceIdentity(
  payload: ArgusPayload,
): Promise<IdentityOutcome> {
  const ex = extractIdentity(payload);
  if (ex.kind === "absent") {
    return {
      present: false,
      verified: false,
      pubkey: null,
      sig_present: false,
      reason: "absent",
    };
  }
  if (ex.kind === "malformed") {
    return {
      present: true,
      verified: false,
      pubkey: ex.pubkey,
      sig_present: ex.sig_present,
      reason: "malformed",
    };
  }
  if (ex.kind === "no_probe_token") {
    return {
      present: true,
      verified: false,
      pubkey: ex.pubkey,
      sig_present: true,
      reason: "probe_token_missing",
    };
  }

  const failReason = await verifySignature(ex.pubkey, ex.sig, ex.h2Token);
  if (failReason) {
    return {
      present: true,
      verified: false,
      pubkey: ex.pubkey,
      sig_present: true,
      reason: failReason,
    };
  }
  return {
    present: true,
    verified: true,
    pubkey: ex.pubkey,
    sig_present: true,
  };
}
