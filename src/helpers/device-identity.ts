/**
 * Device-identity verification helper.
 *
 * The client ships a persistent non-extractable ECDSA P-256 keypair (stored in
 * IndexedDB, generated on first visit). On every submission it sends:
 *
 *   payload.device_identity = { pubkey, sig }
 *
 * where `sig` is the ECDSA signature over a canonical string containing the
 * H2 probe token and the payload's stable and fuzzy hashes. Signing a
 * server-issued token (instead of a plain timestamp) gives us:
 *   - Freshness: the h2-probe token has a 90s HMAC'd TTL
 *   - Unpredictability: attackers can't pre-compute sigs — token is server-chosen
 *   - Payload binding: a signature cannot be replayed with different hashes
 *
 * Failures are non-fatal — we record the outcome on the DDB row so it shows up
 * in analytics, but ingestion always succeeds.
 */

import type { ArgusPayload } from "./payload-schema";

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
 * Canonical signing input for device_identity.
 *
 * Binds the signature to:
 *   - The h2-probe token (per-session unique, IP-bound, 90s TTL)
 *   - The payload's stable + fuzzy hashes (content-bound)
 *
 * Separator `|` is a stable in-band delimiter that can't appear inside
 * h2Token (it's `nonce.expiry.hmac`, all hex+dot) or hashes (all base64).
 * Encoded as UTF-8.
 *
 * A (pubkey, sig) pair from one submission therefore cannot verify against a
 * different submission's hashes.
 */
function deviceIdentitySignedInput(
  h2Token: string,
  stableHash: string,
  fuzzyHash: string,
): Uint8Array {
  const canonical = `${h2Token}|${stableHash}|${fuzzyHash}`;
  return new TextEncoder().encode(canonical);
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
 * Verify the device-identity signature against the payload-binding input.
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

  const isValid = await verifyAgainst(
    key,
    sigBytes,
    deviceIdentitySignedInput(
      inputs.h2Token,
      inputs.stableHash,
      inputs.fuzzyHash,
    ),
  );
  return isValid ? null : "sig_invalid";
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
