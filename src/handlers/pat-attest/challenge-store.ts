/**
 * Bound-challenge store for PAT (#13).
 *
 * The PAT challenge used to be UNBOUND (static): every request got byte-
 * identical challenge bytes, iOS cached the minted token aggressively, and the
 * redeemed token was never single-use — so one real Apple device could farm
 * tokens and replay them.
 *
 * Fix: per request we mint a random 32-byte `redemption_context`, making the
 * challenge unique (iOS mints a FRESH token each time), and store the issued
 * challenge bytes in Valkey keyed by SHA256(challenge). At redemption we
 * atomically GETDEL that key — so the challenge is consumed exactly once. A
 * replayed token finds the key gone and fails verification (its digest no
 * longer matches anything we'll accept).
 *
 * Valkey (shared across warm containers) — NOT an in-Lambda LRU — because the
 * 401 challenge and the iOS redemption retry can land on different containers.
 *
 * Fail-open everywhere: if Valkey is unconfigured or unreachable, `store`
 * returns false and the caller issues an UNBOUND challenge (PAT degrades to
 * the old cacheable behaviour rather than breaking). PAT is a bonus signal, so
 * a Valkey hiccup must never take down the endpoint.
 */
import { createHash, randomBytes } from "crypto";

import { getValkey } from "../../helpers/valkey-client";

const KEY_PREFIX = "pat:chal:";
// Comfortably longer than the iOS challenge→redeem round trip, short enough
// that abandoned challenges evaporate. The signed attestation blob has its own
// 60s hard expiry downstream; this only bounds the unredeemed-challenge window.
const CHALLENGE_TTL_SEC = 300;

/** Binding is active only when Valkey is wired (VPC-attached stages). */
export function bindingEnabled(): boolean {
  return !!process.env.VALKEY_ENDPOINT;
}

/** Fresh 32-byte redemption context for a bound challenge. */
export function newRedemptionContext(): Buffer {
  return randomBytes(32);
}

function keyFor(challengeDigestHex: string): string {
  return `${KEY_PREFIX}${challengeDigestHex}`;
}

/**
 * Store the issued challenge bytes keyed by SHA256(challenge). Returns true on
 * success (bound mode), false if binding is disabled or Valkey errors (caller
 * falls back to an unbound challenge). Never throws.
 */
export async function storeChallenge(challenge: Buffer): Promise<boolean> {
  if (!bindingEnabled()) return false;
  const digestHex = createHash("sha256").update(challenge).digest("hex");
  try {
    await getValkey().set(
      keyFor(digestHex),
      challenge.toString("base64"),
      "EX",
      CHALLENGE_TTL_SEC,
    );
    return true;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      `[pat] storeChallenge failed-open: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
}

/**
 * Atomically fetch-and-delete (GETDEL) the stored challenge for a redeemed
 * token's challenge_digest. Returns the original challenge bytes (now consumed
 * — single use) or null if not found / disabled / Valkey error. Never throws.
 */
export async function consumeChallenge(
  challengeDigest: Buffer,
): Promise<Buffer | null> {
  if (!bindingEnabled()) return null;
  try {
    const v = await getValkey().getdel(keyFor(challengeDigest.toString("hex")));
    return v ? Buffer.from(v, "base64") : null;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      `[pat] consumeChallenge failed-open: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }
}
