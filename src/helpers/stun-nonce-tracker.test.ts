import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _resetStunNonceTrackerForTests,
  _stunNonceTrackerSizeForTests,
  claimStunNonce,
} from "./stun-nonce-tracker";

beforeEach(() => {
  _resetStunNonceTrackerForTests();
});

describe("claimStunNonce", () => {
  it("accepts the first claim and records firstClaim=true", () => {
    const r = claimStunNonce("cipher-A", "session-1", "cpi-x", "1.2.3.4");
    expect(r.accepted).toBe(true);
    expect(r.accepted && r.firstClaim).toBe(true);
  });

  it("is idempotent for the same session — supports SDK/APIGW retries", () => {
    // First submission claims.
    const first = claimStunNonce("cipher-A", "session-1", "cpi-x", "1.2.3.4");
    expect(first.accepted).toBe(true);

    // Retry of the same submission should NOT 409 — same session_id.
    const retry = claimStunNonce("cipher-A", "session-1", "cpi-x", "1.2.3.4");
    expect(retry.accepted).toBe(true);
    expect(retry.accepted && retry.firstClaim).toBe(false);
  });

  it("rejects a different session reclaiming the same candidate", () => {
    claimStunNonce("cipher-A", "session-1", "cpi-x", "1.2.3.4");

    const replay = claimStunNonce("cipher-A", "session-2", "cpi-x", "5.6.7.8");
    expect(replay.accepted).toBe(false);
    if (!replay.accepted) {
      expect(replay.reason).toBe("cross_session_replay");
      expect(replay.firstClaimedBy.sessionId).toBe("session-1");
      expect(replay.firstClaimedBy.ip).toBe("1.2.3.4");
    }
  });

  it("treats distinct cipher values as independent", () => {
    const a = claimStunNonce("cipher-A", "session-1", "cpi-x", "1.1.1.1");
    const b = claimStunNonce("cipher-B", "session-2", "cpi-x", "2.2.2.2");
    expect(a.accepted).toBe(true);
    expect(b.accepted).toBe(true);
    expect(_stunNonceTrackerSizeForTests()).toBe(2);
  });

  it("ignores cpi for matching — replay across merchants still rejected", () => {
    // Same candidate ciphertext, different cpis. The HMAC the sigint STUN
    // server produces doesn't bind to cpi, so two cpis can't legitimately
    // present the same ciphertext — that's a replay, period.
    claimStunNonce("cipher-A", "session-1", "cpi-merchant-A", "1.2.3.4");
    const cross = claimStunNonce(
      "cipher-A",
      "session-2",
      "cpi-merchant-B",
      "1.2.3.4",
    );
    expect(cross.accepted).toBe(false);
  });

  // Note: TTL eviction is not tested here. lru-cache v11 caches its perf
  // clock and refreshes via a setTimeout, so a synthetic time-jump test
  // requires faking Date + performance + setTimeout in a specific order
  // that lru-cache's internals respect. The TTL is a configuration value
  // (STUN_NONCE_TTL_MS); lru-cache's expiry is its own well-tested
  // behavior. The 300s window aligns with sigint-v6-decode's
  // FRESH_WINDOW_SECONDS — past that point the decoder rejects the
  // candidate as stale before it ever reaches this tracker, so a missed
  // LRU eviction has no security consequence anyway.
});

afterEach(() => {
  _resetStunNonceTrackerForTests();
});
