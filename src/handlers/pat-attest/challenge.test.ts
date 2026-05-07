import { describe, it, expect } from "vitest";
import { encodeTokenChallenge } from "./challenge";

describe("encodeTokenChallenge", () => {
  it("encodes the minimum struct: token_type + issuer name only", () => {
    const out = encodeTokenChallenge({ issuerName: "issuer.example" });
    // 2 (type) + 2 (issuer_len) + 14 (issuer) + 1 (rc_len=0) + 2 (origin_len=0) = 21
    expect(out.length).toBe(21);
    expect(out.readUInt16BE(0)).toBe(0x0002);
    expect(out.readUInt16BE(2)).toBe(14);
    expect(out.subarray(4, 18).toString("utf8")).toBe("issuer.example");
    expect(out.readUInt8(18)).toBe(0);
    expect(out.readUInt16BE(19)).toBe(0);
  });

  it("encodes a 32-byte redemption_context", () => {
    const rc = Buffer.alloc(32, 0xab);
    const out = encodeTokenChallenge({
      issuerName: "i.example",
      redemptionContext: rc,
    });
    expect(out.readUInt8(2 + 2 + 9)).toBe(32);
    expect(out.subarray(2 + 2 + 9 + 1, 2 + 2 + 9 + 1 + 32).equals(rc)).toBe(
      true,
    );
  });

  it("rejects redemption_context lengths other than 0 or 32", () => {
    expect(() =>
      encodeTokenChallenge({
        issuerName: "i.example",
        redemptionContext: Buffer.alloc(16),
      }),
    ).toThrow(/redemption_context/);
  });

  it("encodes origin_info when provided", () => {
    const out = encodeTokenChallenge({
      issuerName: "i.example",
      originInfo: "argus.pw",
    });
    const originLenOff = 2 + 2 + 9 + 1; // type + issuer_len + issuer(9) + rc_len(0)
    expect(out.readUInt16BE(originLenOff)).toBe(8);
    expect(out.subarray(originLenOff + 2).toString("utf8")).toBe("argus.pw");
  });
});
