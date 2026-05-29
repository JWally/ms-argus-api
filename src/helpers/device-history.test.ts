import { describe, it, expect } from "vitest";
import {
  encryptDeviceHistory,
  decryptDeviceHistory,
  appendVisit,
  buildFreshBlob,
  hashUserAgent,
  DEVICE_HISTORY_MAX_VISITS,
  type PendingVisit,
} from "./device-history";

const KEY = "a".repeat(64); // 32 bytes hex for SIGINT_AES_KEY input
const PUBKEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsamplePubKeyB64";

function freshBlob(now = 1700000000000) {
  return buildFreshBlob(PUBKEY, now);
}

function pending(overrides: Partial<PendingVisit> = {}): PendingVisit {
  return {
    cpi: "argus_cpi_test_abc",
    session: "s-1",
    ip: "73.93.42.17",
    ua_hash: "deadbeef12345678",
    net_class: "residential",
    country: "US",
    region: "US-CA",
    city: "Mountain View",
    lat: 37.4043,
    lon: -122.0748,
    ...overrides,
  };
}

describe("device-history crypto round-trip", () => {
  it("encrypt/decrypt is lossless on an empty blob", () => {
    const blob = freshBlob();
    const wire = encryptDeviceHistory(blob, KEY);
    const out = decryptDeviceHistory(wire, KEY);
    expect(out.kind).toBe("ok");
    if (out.kind === "ok") expect(out.blob).toEqual(blob);
  });

  it("encrypt/decrypt is lossless on a populated blob", () => {
    let blob = freshBlob();
    for (let i = 0; i < 10; i++) {
      blob = appendVisit(
        blob,
        pending({ session: `s-${i}` }),
        1700000000000 + i * 60000,
      );
    }
    const wire = encryptDeviceHistory(blob, KEY);
    const out = decryptDeviceHistory(wire, KEY);
    expect(out.kind).toBe("ok");
    if (out.kind === "ok") {
      expect(out.blob.visits).toHaveLength(10);
      expect(out.blob.visits[0].session).toBe("s-0");
      expect(out.blob.visits[9].session).toBe("s-9");
    }
  });

  it("absent input → kind=absent (first visit case)", () => {
    expect(decryptDeviceHistory(undefined, KEY).kind).toBe("absent");
    expect(decryptDeviceHistory(null, KEY).kind).toBe("absent");
    expect(decryptDeviceHistory("", KEY).kind).toBe("absent");
  });

  it("non-base64 garbage → auth_fail (bad_base64 or auth_tag)", () => {
    const out = decryptDeviceHistory("not-real-base64!@#$%^", KEY);
    expect(out.kind).toBe("auth_fail");
  });

  it("too-short ciphertext → auth_fail(short)", () => {
    const tooShort = Buffer.alloc(10).toString("base64");
    const out = decryptDeviceHistory(tooShort, KEY);
    expect(out.kind).toBe("auth_fail");
  });

  it("tampered ciphertext → auth_fail(auth_tag)", () => {
    const blob = freshBlob();
    const wire = encryptDeviceHistory(blob, KEY);
    // Flip a bit in the middle of the ciphertext.
    const buf = Buffer.from(wire, "base64");
    buf[20] = buf[20] ^ 0xff;
    const tampered = buf.toString("base64");
    const out = decryptDeviceHistory(tampered, KEY);
    expect(out.kind).toBe("auth_fail");
  });

  it("different key → auth_fail", () => {
    const blob = freshBlob();
    const wire = encryptDeviceHistory(blob, KEY);
    const otherKey = "b".repeat(64);
    const out = decryptDeviceHistory(wire, otherKey);
    expect(out.kind).toBe("auth_fail");
  });
});

describe("appendVisit + pruning", () => {
  it("appends a visit with server timestamp + observed fields", () => {
    const blob = freshBlob(1700000000000);
    const after = appendVisit(blob, pending(), 1700000060000);
    expect(after.visits).toHaveLength(1);
    expect(after.visits[0]).toMatchObject({
      t: 1700000060000,
      ip: "73.93.42.17",
      cpi: "argus_cpi_test_abc",
      session: "s-1",
      ua_hash: "deadbeef12345678",
      net_class: "residential",
      country: "US",
    });
    expect(after.updated).toBe(1700000060000);
  });

  it("prunes oldest when exceeding MAX_VISITS", () => {
    let blob = freshBlob();
    for (let i = 0; i < DEVICE_HISTORY_MAX_VISITS + 5; i++) {
      blob = appendVisit(
        blob,
        pending({ session: `s-${i}` }),
        1700000000000 + i,
      );
    }
    expect(blob.visits).toHaveLength(DEVICE_HISTORY_MAX_VISITS);
    // First retained should be index 5 (oldest 5 pruned).
    expect(blob.visits[0].session).toBe("s-5");
    expect(blob.visits[DEVICE_HISTORY_MAX_VISITS - 1].session).toBe(
      `s-${DEVICE_HISTORY_MAX_VISITS + 4}`,
    );
  });

  it("doesn't mutate the input blob", () => {
    const blob = freshBlob();
    const snapshot = JSON.stringify(blob);
    appendVisit(blob, pending());
    expect(JSON.stringify(blob)).toBe(snapshot);
  });
});

describe("buildFreshBlob", () => {
  it("returns a v1 blob bound to the pubkey with no visits", () => {
    const blob = buildFreshBlob("test-pubkey", 1234);
    expect(blob).toEqual({
      v: 1,
      id: "test-pubkey",
      created: 1234,
      updated: 1234,
      visits: [],
    });
  });
});

describe("hashUserAgent", () => {
  it("returns null for absent/empty UA", () => {
    expect(hashUserAgent(undefined)).toBeNull();
    expect(hashUserAgent(null)).toBeNull();
    expect(hashUserAgent("")).toBeNull();
  });

  it("returns 16-hex-char prefix of SHA-256", () => {
    const h = hashUserAgent("Mozilla/5.0");
    expect(h).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is stable across calls", () => {
    expect(hashUserAgent("X")).toBe(hashUserAgent("X"));
  });
});
