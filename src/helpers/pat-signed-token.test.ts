import { describe, it, expect } from "vitest";
import { createHmac } from "crypto";
import {
  signPatAttestation,
  verifyPatAttestation,
  DEFAULT_TTL_MS,
} from "./pat-signed-token";

const KEY = "a".repeat(64); // 32 bytes hex
const OTHER_KEY = "b".repeat(64);
const SRC_IP = "203.0.113.42";

function fixture(
  overrides: Partial<Parameters<typeof signPatAttestation>[0]> = {},
) {
  return {
    issuer: "demo-issuer.private-access-tokens.fastly.com",
    srcIp: SRC_IP,
    tokenHash: "deadbeef".repeat(8),
    sigintAesKeyHex: KEY,
    nowMs: 1_700_000_000_000,
    ttlMs: DEFAULT_TTL_MS,
    ...overrides,
  };
}

describe("signPatAttestation", () => {
  it("produces a `<b64url>.<hex>` token", () => {
    const tok = signPatAttestation(fixture());
    expect(tok).toMatch(/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/);
  });
});

describe("verifyPatAttestation", () => {
  it("round-trips a freshly signed token", () => {
    const tok = signPatAttestation(fixture());
    const r = verifyPatAttestation(tok, SRC_IP, KEY, 1_700_000_000_000);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.payload.attested).toBe(true);
      expect(r.payload.type).toBe("pat");
      expect(r.payload.issuer).toBe(
        "demo-issuer.private-access-tokens.fastly.com",
      );
      expect(r.payload.src_ip).toBe(SRC_IP);
    }
  });

  it("rejects a token signed with a different key", () => {
    const tok = signPatAttestation(fixture());
    const r = verifyPatAttestation(tok, SRC_IP, OTHER_KEY, 1_700_000_000_000);
    expect(r).toEqual({ ok: false, reason: "BAD_HMAC" });
  });

  it("rejects a token redeemed from a different source IP", () => {
    const tok = signPatAttestation(fixture());
    const r = verifyPatAttestation(tok, "198.51.100.1", KEY, 1_700_000_000_000);
    expect(r).toEqual({ ok: false, reason: "WRONG_IP" });
  });

  it("rejects a token past its expiry", () => {
    const tok = signPatAttestation(fixture());
    const r = verifyPatAttestation(
      tok,
      SRC_IP,
      KEY,
      1_700_000_000_000 + DEFAULT_TTL_MS + 1_000,
    );
    expect(r).toEqual({ ok: false, reason: "EXPIRED" });
  });

  it("rejects malformed (no separator) tokens", () => {
    const r = verifyPatAttestation("notatoken", SRC_IP, KEY);
    expect(r).toEqual({ ok: false, reason: "MALFORMED" });
  });

  it("rejects a token whose b64 payload was tampered (HMAC over original)", () => {
    const tok = signPatAttestation(fixture());
    // Replace the b64 part with the same length of `A`s; HMAC is now wrong.
    const sep = tok.lastIndexOf(".");
    const b64 = tok.slice(0, sep);
    const mac = tok.slice(sep + 1);
    const tampered = "A".repeat(b64.length) + "." + mac;
    const r = verifyPatAttestation(tampered, SRC_IP, KEY);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("BAD_HMAC");
  });

  it("rejects a token whose payload doesn't match the expected schema", () => {
    // Hand-craft a token with a malformed payload but correct HMAC over it.
    const badPayload = Buffer.from(JSON.stringify({ wrong: "shape" }), "utf8");
    const b64 = badPayload
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const mac = createHmac("sha256", Buffer.from(KEY, "hex").subarray(0, 32))
      .update(b64)
      .digest("hex");
    const r = verifyPatAttestation(`${b64}.${mac}`, SRC_IP, KEY);
    expect(r).toEqual({ ok: false, reason: "BAD_PAYLOAD" });
  });
});
