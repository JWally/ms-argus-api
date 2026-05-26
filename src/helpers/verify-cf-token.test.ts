import { describe, it, expect } from "vitest";
import {
  sipHash24,
  verifyCfToken,
  verifyCfCookie,
  extractFpidCookie,
} from "./verify-cf-token";

// Standard RFC SipHash-2-4 test key (bytes 00..0f, zero-padded to 64 hex chars)
const RFC_KEY = "000102030405060708090a0b0c0d0e0f" + "00".repeat(16);

describe("sipHash24", () => {
  it("matches RFC vector for empty message", () => {
    expect(sipHash24(RFC_KEY, "")).toBe("310e0edd47db6f72");
  });

  it("matches RFC vector for single null byte", () => {
    expect(sipHash24(RFC_KEY, String.fromCharCode(0))).toBe("fd67dc93c539f874");
  });

  it("matches RFC vector for 15-byte message", () => {
    let msg = "";
    for (let i = 0; i < 15; i++) msg += String.fromCharCode(i);
    expect(sipHash24(RFC_KEY, msg)).toBe("e545be4961ca29a1");
  });

  it("matches RFC vector for 63-byte message", () => {
    let msg = "";
    for (let i = 0; i < 63; i++) msg += String.fromCharCode(i);
    expect(sipHash24(RFC_KEY, msg)).toBe("724506eb4c328a95");
  });

  it("handles UTF-8 encoded input", () => {
    // Different inputs should produce different outputs; stability check
    const a = sipHash24(RFC_KEY, "héllo");
    const b = sipHash24(RFC_KEY, "hello");
    expect(a).not.toBe(b);
    expect(a).toHaveLength(16);
  });

  it("rejects a too-short key", () => {
    expect(() => sipHash24("deadbeef", "x")).toThrow(/SipHash key/);
  });
});

describe("verifyCfToken", () => {
  const key = "f5caa84bfeaf811c".repeat(4);
  const now = 1_700_000_000;
  const id = "abcdef12-3456-7890-abcd-ef1234567890";
  const issuedAt = 1_699_999_999;
  const ip = "1.2.3.4";
  const asn = "13335";

  function makeToken(ts: number) {
    const canonical = `${id}|${issuedAt}|${ip}|${asn}|${ts}`;
    return {
      id,
      issuedAt,
      ip,
      asn,
      ts,
      sig: sipHash24(key, canonical),
    };
  }

  it("verifies a legitimate token as not tampered and not expired", () => {
    const token = makeToken(now);
    expect(verifyCfToken(token, key, now)).toEqual({
      expired: false,
      tampered: false,
      ageSec: 0,
    });
  });

  it("returns ageSec = now - ts (positive for stale tokens)", () => {
    const token = makeToken(now - 120); // 120s past
    const r = verifyCfToken(token, key, now);
    expect(r.ageSec).toBe(120);
    expect(r.expired).toBe(true); // outside ±90s
    expect(r.tampered).toBe(false); // sig still valid
  });

  it("returns negative ageSec for future-dated tokens", () => {
    const token = makeToken(now + 200); // 200s in the future
    const r = verifyCfToken(token, key, now);
    expect(r.ageSec).toBe(-200);
    expect(r.expired).toBe(true);
  });

  it("returns ageSec=null when ts is missing", () => {
    const { ts: _ts, ...withoutTs } = makeToken(now);
    expect(verifyCfToken(withoutTs, key, now).ageSec).toBeNull();
  });

  it("flags tampered when the sig does not match", () => {
    const token = makeToken(now);
    token.sig = "deadbeefdeadbeef";
    expect(verifyCfToken(token, key, now).tampered).toBe(true);
  });

  it("flags tampered when a signed field is modified", () => {
    const token = makeToken(now);
    token.ip = "5.6.7.8";
    expect(verifyCfToken(token, key, now).tampered).toBe(true);
  });

  it("flags expired when ts is outside the window", () => {
    const token = makeToken(now - 1000);
    expect(verifyCfToken(token, key, now).expired).toBe(true);
  });

  it("flags expired when ts is in the future beyond window", () => {
    const token = makeToken(now + 1000);
    expect(verifyCfToken(token, key, now).expired).toBe(true);
  });

  it("fails closed when sig is missing", () => {
    expect(
      verifyCfToken({ id, issuedAt, ts: now, ip, asn }, key, now).tampered,
    ).toBe(true);
  });

  it("fails closed when required fields are missing", () => {
    expect(verifyCfToken({}, key, now).tampered).toBe(true);
    expect(verifyCfToken({}, key, now).expired).toBe(true);
  });
});

describe("verifyCfCookie", () => {
  const key = "f5caa84bfeaf811c".repeat(4);
  const id = "abcdef12-3456-7890-abcd-ef1234567890";
  const issuedAt = 1_700_000_000;

  it("verifies a properly-signed cookie", () => {
    const sig = sipHash24(key, `fpid|${id}|${issuedAt}`);
    const cookie = `${id}_${issuedAt}.${sig}`;
    expect(verifyCfCookie(cookie, key)).toEqual({ valid: true, id, issuedAt });
  });

  it("rejects a cookie with a bad sig", () => {
    const cookie = `${id}_${issuedAt}.deadbeefdeadbeef`;
    const r = verifyCfCookie(cookie, key);
    expect(r.valid).toBe(false);
    // Still parses id/issuedAt so callers can log them
    expect(r.id).toBe(id);
    expect(r.issuedAt).toBe(issuedAt);
  });

  it("rejects a malformed cookie (no separator)", () => {
    expect(verifyCfCookie("not-a-cookie", key)).toEqual({ valid: false });
  });

  it("rejects a cookie with an invalid uuid", () => {
    expect(verifyCfCookie("not-uuid_123.cafecafecafecafe", key)).toEqual({
      valid: false,
    });
  });

  it("rejects a cookie with a non-numeric timestamp", () => {
    expect(verifyCfCookie(`${id}_abc.cafecafecafecafe`, key)).toEqual({
      valid: false,
    });
  });

  it("rejects a cookie with no sig delimiter", () => {
    expect(verifyCfCookie(`${id}_${issuedAt}`, key)).toEqual({
      valid: false,
    });
  });
});

describe("extractFpidCookie", () => {
  it("returns undefined when cookies are absent", () => {
    expect(extractFpidCookie(undefined)).toBeUndefined();
    expect(extractFpidCookie([])).toBeUndefined();
  });

  it("extracts from API Gateway V2 array form (one cookie per entry)", () => {
    expect(extractFpidCookie(["_fpid=abc123", "other=x"])).toBe("abc123");
  });

  it("extracts from combined form (multiple cookies in one entry)", () => {
    expect(extractFpidCookie(["other=x; _fpid=abc123; third=y"])).toBe(
      "abc123",
    );
  });

  it("returns undefined when _fpid is not present", () => {
    expect(extractFpidCookie(["a=1", "b=2"])).toBeUndefined();
  });
});
