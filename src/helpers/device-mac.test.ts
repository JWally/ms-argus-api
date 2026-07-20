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
import { createHmac } from "node:crypto";
import { deviceMacRejectionReason, verifyDeviceMac } from "./device-mac";

const SESSION = "session-token-abc";
const LEGACY_SLICE_NAMES = [
  "css",
  "engine",
  "math",
  "headless",
  "lies",
  "trash",
  "shielding",
  "incognito",
  "intl",
  "navigator",
  "screen",
  "status",
  "timezone",
  "timing",
  "cssMedia",
  "webrtc",
  "windowPrefixes",
  "workerScope",
  "errors",
  "canvas",
  "audio",
  "fonts",
] as const;

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
      worker_attest: {
        ua: "Mozilla/5.0",
        hardwareConcurrency: 8,
        getRandomValuesNative: true,
      },
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

/** Reproduce the retired 22-slice wire contract so it stays rejected. */
function legacyMacFor(payload: Record<string, unknown>): string {
  const device = payload.device as Record<string, unknown>;
  const material = [
    SESSION,
    payload.sigintTls,
    (payload.device_identity as Record<string, unknown>).pubkey,
  ].join(String.fromCharCode(0));
  const key = createHmac(
    "md5",
    Buffer.from([0x9c, 0x2f, 0xa1, 0x7b, 0x4e, 0xd3, 0x68, 0x05]),
  )
    .update(material)
    .digest();
  const chunks = LEGACY_SLICE_NAMES.flatMap((name, index) => {
    const id = Buffer.alloc(4);
    id.writeUInt32BE(0x50 + index);
    return [id, Buffer.from(JSON.stringify(device[name] ?? null))];
  });
  return createHmac("md5", key).update(Buffer.concat(chunks)).digest("hex");
}

describe("verifyDeviceMac", () => {
  it("classifies a payload with no device.mac as absent", () => {
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

  it("rejects a legacy 22-slice MAC", () => {
    const payload = samplePayload();
    (payload.device as Record<string, unknown>).mac = legacyMacFor(payload);
    expect(verifyDeviceMac(payload, { sessionToken: SESSION }).kind).toBe(
      "mismatch",
    );
  });

  it("requires worker attestation on every current payload", () => {
    const payload = seal(samplePayload());
    delete (payload.device as Record<string, unknown>).worker_attest;
    expect(verifyDeviceMac(payload, { sessionToken: SESSION }).kind).toBe(
      "absent",
    );
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

describe("deviceMacRejectionReason", () => {
  it("requires the current MAC instead of preserving a missing-MAC grace path", () => {
    expect(deviceMacRejectionReason({ kind: "absent" })).toBe(
      "device_mac_required",
    );
  });

  it("rejects mismatches and accepts only a verified MAC", () => {
    expect(
      deviceMacRejectionReason({
        kind: "mismatch",
        expected: "expected",
        received: "received",
      }),
    ).toBe("device_mac_mismatch");
    expect(deviceMacRejectionReason({ kind: "ok" })).toBeNull();
  });
});
