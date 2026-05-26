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
  | {
      kind: "ok";
      pubkey: string;
      sig: string;
      h2Token: string;
      stableHash: string;
      fuzzyHash: string;
    };

/**
 * Pull `pubkey`, `sig`, `sigintH2Token`, and the payload hashes from the
 * payload, classifying any missing-or-malformed case. Keeps the verify
 * function's branching linear.
 */
/** Read a string field from an object, returning "" when missing/non-string. */
function strField(o: unknown, key: string): string {
  const v = (o as Record<string, unknown> | undefined)?.[key];
  return typeof v === "string" ? v : "";
}

function extractIdentity(payload: ArgusPayload): Extracted {
  const identity = payload.device_identity;
  if (!identity || typeof identity !== "object") return { kind: "absent" };
  const pubkey = strField(identity, "pubkey");
  const sig = strField(identity, "sig");
  const sigPresent = sig.length > 0;
  if (pubkey.length === 0 || !sigPresent) {
    return {
      kind: "malformed",
      pubkey: pubkey || null,
      sig_present: sigPresent,
    };
  }
  const h2Token = strField(payload, "sigintH2Token");
  if (h2Token.length === 0) return { kind: "no_probe_token", pubkey };
  return {
    kind: "ok",
    pubkey,
    sig,
    h2Token,
    stableHash: strField(payload.hashes, "stable"),
    fuzzyHash: strField(payload.hashes, "fuzzy"),
  };
}

/**
 * Canonical v2 signing input for device_identity.
 *
 * Binds the signature to:
 *   - The h2-probe token (per-session unique, IP-bound, 90s TTL)
 *   - The payload's stable + fuzzy hashes (content-bound)
 *
 * Separator `|` is a stable in-band delimiter that can't appear inside
 * h2Token (it's `nonce.expiry.hmac`, all hex+dot) or hashes (all base64).
 * Encoded as UTF-8.
 *
 * Pre-2026-05-26 the signing input was `xor(h2Token, DEVICE_IDENTITY_XOR_KEY)`
 * — see deviceIdentityXorInputLegacy below. That construction was both
 * trivially mintable (XOR key was a public constant) AND replay-able
 * across payloads (no hash binding). The v2 input closes the replay
 * primitive: a (pubkey, sig) pair from one submission no longer
 * verifies against a different submission's hashes.
 */
function deviceIdentitySignedInputV2(
  h2Token: string,
  stableHash: string,
  fuzzyHash: string,
): Uint8Array {
  const canonical = `${h2Token}|${stableHash}|${fuzzyHash}`;
  return new TextEncoder().encode(canonical);
}

/**
 * Legacy v1 signing input — kept ONLY for backward compatibility during
 * the SDK rollout window. Delete after the bytecode update has fully
 * propagated and metrics show no v1-format verifications.
 *
 * @deprecated remove after SDK rollout
 */
function deviceIdentityXorInputLegacy(h2Token: string): Uint8Array {
  return xorBytes(new TextEncoder().encode(h2Token), DEVICE_IDENTITY_XOR_KEY);
}

interface VerifyInputs {
  pubkeyB64: string;
  sigB64: string;
  h2Token: string;
  stableHash: string;
  fuzzyHash: string;
}

/**
 * ECDSA verify against a specific signed input. Returns null on success,
 * a reason string on failure.
 */
async function verifyAgainst(
  key: CryptoKey,
  sigBytes: Uint8Array,
  signedInput: Uint8Array,
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes,
      signedInput,
    );
  } catch {
    return false;
  }
}

/**
 * Verify the device-identity signature against the payload-binding input
 * (v2). Falls back to the legacy XOR input (v1) ONLY during the SDK
 * rollout window so older bundles continue to verify. Both paths
 * produce the same IdentityOutcome from the analyzer's POV.
 */
async function verifySignature(
  inputs: VerifyInputs,
): Promise<IdentityFailReason | null> {
  const key = await importPubkey(inputs.pubkeyB64);
  if (!key) return "pubkey_invalid";

  let sigBytes: Uint8Array;
  try {
    sigBytes = b64ToBytes(inputs.sigB64);
  } catch {
    return "malformed";
  }

  // v2 first — payload-bound input.
  const v2Ok = await verifyAgainst(
    key,
    sigBytes,
    deviceIdentitySignedInputV2(
      inputs.h2Token,
      inputs.stableHash,
      inputs.fuzzyHash,
    ),
  );
  if (v2Ok) return null;

  // v1 fallback — legacy XOR input. To be removed after SDK rollout.
  const v1Ok = await verifyAgainst(
    key,
    sigBytes,
    deviceIdentityXorInputLegacy(inputs.h2Token),
  );
  if (v1Ok) return null;

  return "sig_invalid";
}

/** Map a non-"ok" extraction result to its IdentityOutcome. */
function failedExtractionOutcome(
  ex: Exclude<Extracted, { kind: "ok" }>,
): IdentityOutcome {
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
  // ex.kind === "no_probe_token"
  return {
    present: true,
    verified: false,
    pubkey: ex.pubkey,
    sig_present: true,
    reason: "probe_token_missing",
  };
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
  if (ex.kind !== "ok") return failedExtractionOutcome(ex);

  const failReason = await verifySignature({
    pubkeyB64: ex.pubkey,
    sigB64: ex.sig,
    h2Token: ex.h2Token,
    stableHash: ex.stableHash,
    fuzzyHash: ex.fuzzyHash,
  });
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
