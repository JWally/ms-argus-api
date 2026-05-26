import { describe, it, expect } from "vitest";
import { redeemPatToken } from "./redeem-pat-token";
import { signPatAttestation } from "./pat-signed-token";
import type { ArgusPayload } from "./payload-schema";

const KEY = "a".repeat(64);
const SRC_IP = "203.0.113.42";

function basePayload(overrides: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    identifiers: { session_id: "s" },
    hashes: { stable: "x", fuzzy: "y" },
    device: {} as ArgusPayload["device"],
    ...overrides,
  };
}

describe("redeemPatToken", () => {
  it("attaches payload.pat on a valid token", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: KEY,
    });
    expect(out.pat).toBeDefined();
    expect(out.pat?.attested).toBe(true);
    expect(out.pat?.issuer).toBe(
      "demo-issuer.private-access-tokens.fastly.com",
    );
    expect(out.pat?.tokenHash).toBe("deadbeef".repeat(8));
  });

  it("drops the field silently when there's no patToken", () => {
    const out = redeemPatToken(basePayload(), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: KEY,
    });
    expect(out.pat).toBeUndefined();
  });

  it("drops the field when source IP doesn't match", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: "198.51.100.1",
      sigintAesKeyHex: KEY,
    });
    expect(out.pat).toBeUndefined();
  });

  it("drops the field when the HMAC key doesn't match", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: "b".repeat(64),
    });
    expect(out.pat).toBeUndefined();
  });

  // ── patAttempt telemetry (added 2026-05-25 for tier-60 scoring) ───────

  it("stamps patAttempt={attempted:false} when no patToken shipped", () => {
    const out = redeemPatToken(basePayload(), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: KEY,
    });
    expect(out.patAttempt).toEqual({ attempted: false, verified: false });
  });

  it("stamps patAttempt={attempted:true, verified:true} on success", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: KEY,
    });
    expect(out.patAttempt).toEqual({ attempted: true, verified: true });
  });

  it("stamps patAttempt={attempted:true, verified:false, reason} on bad IP", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: "198.51.100.1",
      sigintAesKeyHex: KEY,
    });
    expect(out.patAttempt?.attempted).toBe(true);
    expect(out.patAttempt?.verified).toBe(false);
    expect(out.patAttempt?.reason).toBeDefined();
  });

  it("stamps patAttempt={attempted:true, verified:false} on bad HMAC", () => {
    const token = signPatAttestation({
      issuer: "demo-issuer.private-access-tokens.fastly.com",
      srcIp: SRC_IP,
      tokenHash: "deadbeef".repeat(8),
      sigintAesKeyHex: KEY,
    });
    const out = redeemPatToken(basePayload({ patToken: token }), {
      expectedSrcIp: SRC_IP,
      sigintAesKeyHex: "b".repeat(64),
    });
    expect(out.patAttempt?.attempted).toBe(true);
    expect(out.patAttempt?.verified).toBe(false);
  });
});
