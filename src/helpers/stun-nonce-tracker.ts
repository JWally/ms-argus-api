/**
 * Single-use enforcement for STUN attestation candidates.
 *
 * Today the sigint STUN server signs `(clientIPv4 | epoch | nonce)` with
 * an HMAC keyed by the shared SIGINT_AES_KEY. The signing input does NOT
 * include any session identifier, so a captured candidate is replayable
 * across sessions for up to FRESH_WINDOW_SECONDS (300s today). This module
 * adds a single-use gate at the API: each candidate's ciphertext can be
 * redeemed by exactly one session_id; a different session attempting to
 * reuse it gets HTTP 409.
 *
 * Storage is an in-memory LRU per Lambda container. That is intentional
 * for cost/latency — sub-microsecond hit, zero new infrastructure — but
 * carries one caveat called out below.
 *
 * ── Multi-container caveat ─────────────────────────────────────────────
 * Lambda doesn't share memory across warm containers. With N concurrent
 * containers, an attacker who fans out N parallel submissions of the
 * same captured nonce can succeed up to N times before the trailing
 * containers' LRUs catch up. Practical N at dev-jw scale: 1-3. At prod
 * burst: 5-20. Strictly better than today's ∞ reuses, strictly worse
 * than a DDB ConditionExpression's exactly-once. If fraud telemetry
 * later shows fan-out being exploited, promote to a shared `OnceTracker`
 * backed by DDB (see WebrtcStunReplay metric for the signal).
 *
 * Idempotency: the LRU value is the claiming session_id. A re-claim by
 * the SAME session is idempotent — needed because SDK or API Gateway
 * may retry on transient network failures and we don't want to 409 a
 * legitimate retry.
 */

import { LRUCache } from "lru-cache";

// Matches FRESH_WINDOW_SECONDS in sigint-v6-decode.ts — past this point
// the v6 decoder already rejects the candidate as stale, so tracking it
// past 300s would be wasted memory.
const STUN_NONCE_TTL_MS = 300 * 1000;

// Generous bound. At ~50 bytes/entry this is ~2.5 MB on a 1024 MB Lambda,
// negligible. The LRU's job is to bound memory for the rare burst; under
// normal load TTL eviction reaps entries first.
const STUN_NONCE_MAX_ENTRIES = 50_000;

interface ClaimRecord {
  sessionId: string;
  cpi: string;
  ip: string;
  claimedAt: number;
}

const tracker = new LRUCache<string, ClaimRecord>({
  max: STUN_NONCE_MAX_ENTRIES,
  ttl: STUN_NONCE_TTL_MS,
  ttlAutopurge: true,
});

export type StunClaimOutcome =
  | { accepted: true; firstClaim: boolean }
  | {
      accepted: false;
      reason: "cross_session_replay";
      firstClaimedBy: ClaimRecord;
    };

/**
 * Attempt to claim a STUN attestation for a session.
 *
 * - First call for a given cipherB64 → accepted (firstClaim=true).
 * - Subsequent call by the same session → accepted (firstClaim=false) — idempotent retry.
 * - Subsequent call by a DIFFERENT session → rejected, caller should 409.
 *
 * @param cipherB64 - Canonical key (16-byte ciphertext, base64) from `DecodedV6Payload`.
 * @param sessionId - Session claiming this attestation.
 * @param cpi       - Merchant cpi (recorded for forensics; not part of the key).
 * @param ip        - Attested IP from the decoded payload (recorded for forensics).
 */
export function claimStunNonce(
  cipherB64: string,
  sessionId: string,
  cpi: string,
  ip: string,
): StunClaimOutcome {
  const existing = tracker.get(cipherB64);
  if (!existing) {
    tracker.set(cipherB64, { sessionId, cpi, ip, claimedAt: Date.now() });
    return { accepted: true, firstClaim: true };
  }
  if (existing.sessionId === sessionId) {
    return { accepted: true, firstClaim: false };
  }
  return {
    accepted: false,
    reason: "cross_session_replay",
    firstClaimedBy: existing,
  };
}

/** Test-only: clear the tracker. Production code must not call this. */
export function _resetStunNonceTrackerForTests(): void {
  tracker.clear();
}

/** Test-only: peek at the size for assertions. */
export function _stunNonceTrackerSizeForTests(): number {
  return tracker.size;
}
