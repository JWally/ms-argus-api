/**
 * Contract test for verifyDeviceMac — the server-side replay of the SDK's
 * device.mac HMAC chain. This is the integrity equivalent of the pair
 * stolen-token guard: the worker (SCIF) is only a bar-raiser; THIS is the
 * actual boundary. base-handler rejects on 'mismatch' (400 device_mac_mismatch),
 * so a regression that made this fail OPEN would let a tampered/self-minted
 * payload through. Lock it down.
 *
 * The valid MAC is never recomputed here (that would just duplicate the
 * algorithm and drift with it). Instead we let verifyDeviceMac itself hand us
 * the `expected` MAC via a first 'mismatch' outcome, then resubmit it — so this
 * test tracks the implementation automatically and only asserts the OUTCOMES.
 */
import { describe, it, expect } from "vitest";
import { verifyDeviceMac } from "./device-mac";

const SESSION = "session-token-abc";

/** A representative device payload (a few real slices + sigint key material). */
function samplePayload(): Record<string, unknown> {
  return {
    sigintTls: "ja4-tls-fingerprint",
    device_identity: { pubkey: "device-pub-key" },
    device: {
      navigator: { userAgent: "Mozilla/5.0", languages: ["en-US"] },
      canvas: "canvas-hash-abc123",
      audio: 124.04347527516074,
      screen: { w: 1920, h: 1080 },
      mac: "00000000000000000000000000000000", // wrong on purpose
    },
  };
}

/** Ask the verifier for the correct MAC by reading it off a mismatch. */
function validMacFor(payload: Record<string, unknown>): string {
  const outcome = verifyDeviceMac(payload, { sessionToken: SESSION });
  if (outcome.kind !== "mismatch") {
    throw new Error(
      `expected a mismatch to read the MAC from, got ${outcome.kind}`,
    );
  }
  return outcome.expected;
}

/** Deep-clone so slice mutations don't bleed across cases. */
function seal(payload: Record<string, unknown>): Record<string, unknown> {
  const p = structuredClone(payload);
  (p.device as Record<string, unknown>).mac = validMacFor(payload);
  return p;
}

describe("verifyDeviceMac", () => {
  it("returns 'absent' for an old-bundle payload with no device.mac", () => {
    expect(verifyDeviceMac({}, { sessionToken: SESSION }).kind).toBe("absent");
    expect(
      verifyDeviceMac({ device: {} }, { sessionToken: SESSION }).kind,
    ).toBe("absent");
    expect(verifyDeviceMac(null, { sessionToken: SESSION }).kind).toBe(
      "absent",
    );
  });

  it("returns 'ok' for a correctly-MAC'd payload", () => {
    const good = seal(samplePayload());
    expect(verifyDeviceMac(good, { sessionToken: SESSION }).kind).toBe("ok");
  });

  it("rejects a tampered device slice (same MAC, mutated value)", () => {
    const p = seal(samplePayload());
    (p.device as Record<string, unknown>).canvas = "canvas-hash-FORGED";
    expect(verifyDeviceMac(p, { sessionToken: SESSION }).kind).toBe("mismatch");
  });

  it("rejects cross-session replay (valid MAC, different sessionToken)", () => {
    const p = seal(samplePayload());
    expect(
      verifyDeviceMac(p, { sessionToken: "some-other-session" }).kind,
    ).toBe("mismatch");
  });

  it("rejects tampered sigint key material (MAC binds it)", () => {
    const p = seal(samplePayload());
    p.sigintTls = "different-ja4";
    expect(verifyDeviceMac(p, { sessionToken: SESSION }).kind).toBe("mismatch");
  });

  it("rejects a self-minted garbage MAC", () => {
    const p = samplePayload();
    (p.device as Record<string, unknown>).mac =
      "deadbeefdeadbeefdeadbeefdeadbeef";
    expect(verifyDeviceMac(p, { sessionToken: SESSION }).kind).toBe("mismatch");
  });
});
