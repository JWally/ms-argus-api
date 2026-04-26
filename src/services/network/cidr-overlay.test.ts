import { describe, it, expect } from "vitest";
import { lookupCidrOverlay } from "./cidr-overlay";

describe("lookupCidrOverlay — AT&T 7018 mixed-use disambiguation", () => {
  it("classifies the AT&T cellular block (107.64/10) as mobile", () => {
    expect(lookupCidrOverlay("107.116.185.73")?.category).toBe("mobile");
    expect(lookupCidrOverlay("107.115.171.50")?.category).toBe("mobile");
    expect(lookupCidrOverlay("107.116.156.97")?.category).toBe("mobile");
    expect(lookupCidrOverlay("107.115.176.65")?.category).toBe("mobile");
  });

  it("classifies the AT&T U-Verse residential block (107.192/11) as residential", () => {
    expect(lookupCidrOverlay("107.210.133.127")?.category).toBe("residential");
  });

  it("classifies the AT&T SBCIS-SBIS residential blocks as residential", () => {
    expect(lookupCidrOverlay("108.243.197.41")?.category).toBe("residential");
    expect(lookupCidrOverlay("99.100.141.186")?.category).toBe("residential");
  });

  it("classifies the AT&T Mobility 166.x blocks as mobile", () => {
    expect(lookupCidrOverlay("166.137.1.1")?.category).toBe("mobile");
    expect(lookupCidrOverlay("166.196.50.50")?.category).toBe("mobile");
  });
});

describe("lookupCidrOverlay — T-Mobile cellular", () => {
  it("172.56.0.0/14 is mobile", () => {
    expect(lookupCidrOverlay("172.58.11.182")?.category).toBe("mobile");
    expect(lookupCidrOverlay("172.59.16.190")?.category).toBe("mobile");
  });
});

describe("lookupCidrOverlay — Verizon Wireless", () => {
  it("174.192/9 is mobile", () => {
    expect(lookupCidrOverlay("174.193.0.1")?.category).toBe("mobile");
  });
});

describe("lookupCidrOverlay — US Cellular (ASN 6614)", () => {
  it("166.181.x is mobile (USL-63 block)", () => {
    expect(lookupCidrOverlay("166.181.82.203")?.category).toBe("mobile");
  });
  it("166.182.x is mobile (USL-63 block)", () => {
    expect(lookupCidrOverlay("166.182.255.43")?.category).toBe("mobile");
  });
  it("166.180.255.255 (one below) is not in USCC blocks", () => {
    const r = lookupCidrOverlay("166.180.255.255");
    if (r) expect(r.note).not.toContain("US Cellular");
  });
});

describe("lookupCidrOverlay — RFC6598 CGNAT shared space", () => {
  it("100.64/10 is mobile (carrier CGNAT)", () => {
    expect(lookupCidrOverlay("100.64.5.5")?.category).toBe("mobile");
    expect(lookupCidrOverlay("100.127.255.254")?.category).toBe("mobile");
  });
});

describe("lookupCidrOverlay — non-matches", () => {
  it("returns null for IPs outside any overlay range", () => {
    expect(lookupCidrOverlay("8.8.8.8")).toBeNull();
    expect(lookupCidrOverlay("1.2.3.4")).toBeNull();
    expect(lookupCidrOverlay("52.32.41.53")).toBeNull(); // AWS IP
  });

  it("returns null for malformed input", () => {
    expect(lookupCidrOverlay("not-an-ip")).toBeNull();
    expect(lookupCidrOverlay("1.2.3")).toBeNull();
  });
});

/**
 * CIDR boundary tests — these verify the binary search correctly identifies
 * the first IP, last IP, and the IPs immediately outside each overlay
 * range. Off-by-one errors here would silently misclassify whole subnets.
 *
 * The /9 and /10 prefixes specifically trigger the JS signed-int32 trap
 * (high IPs become negative under bitwise ops), which previously caused
 * 174.193.0.1 to miss its containing /9 and 8.8.8.8 to falsely match
 * 32.128.0.0/9. Keeping these tests in tree guards against regression.
 */
describe("lookupCidrOverlay — boundary edges (AT&T mobility 107.64.0.0/10)", () => {
  it("first IP of the range matches", () => {
    expect(lookupCidrOverlay("107.64.0.0")?.category).toBe("mobile");
  });
  it("interior IP matches", () => {
    expect(lookupCidrOverlay("107.95.128.50")?.category).toBe("mobile");
  });
  it("last IP of the range matches", () => {
    expect(lookupCidrOverlay("107.127.255.255")?.category).toBe("mobile");
  });
  it("one past the last IP — falls into the /11 below or null gap", () => {
    // 107.128.0.0 is between the mobility /10 (ends 107.127.255.255) and
    // the residential /11 (starts 107.192.0.0). Should NOT match mobile.
    const r = lookupCidrOverlay("107.128.0.0");
    if (r) expect(r.category).not.toBe("mobile");
  });
  it("one before the first IP — must not be classified as mobile", () => {
    // 107.63.255.255 sits just below the /10. Should not match.
    const r = lookupCidrOverlay("107.63.255.255");
    if (r) expect(r.category).not.toBe("mobile");
  });
});

describe("lookupCidrOverlay — boundary edges (AT&T residential 107.192.0.0/11)", () => {
  it("first IP matches as residential", () => {
    expect(lookupCidrOverlay("107.192.0.0")?.category).toBe("residential");
  });
  it("last IP of /11 matches as residential", () => {
    // 107.192.0.0/11 covers 107.192.0.0 - 107.223.255.255
    expect(lookupCidrOverlay("107.223.255.255")?.category).toBe("residential");
  });
  it("one past /11 must not be residential under this rule", () => {
    const r = lookupCidrOverlay("107.224.0.0");
    if (r) expect(r.note).not.toContain("SIS-80-4-2012");
  });
});

describe("lookupCidrOverlay — JS signed-int32 trap (Verizon /9)", () => {
  // 174.192.0.0/9 = 174.128.0.0 - 174.255.255.255. High-IP /9 entries hit
  // the signed-int32 issue if the binary search isn't unsigned-clean.
  it("first IP of the /9 (mask-aligned start) matches mobile", () => {
    expect(lookupCidrOverlay("174.128.0.0")?.category).toBe("mobile");
  });
  it("the mid IP of the /9 matches mobile", () => {
    expect(lookupCidrOverlay("174.193.0.1")?.category).toBe("mobile");
  });
  it("the last IP of the /9 matches mobile", () => {
    expect(lookupCidrOverlay("174.255.255.255")?.category).toBe("mobile");
  });
  it("8.8.8.8 (well below all entries) MUST NOT spuriously match", () => {
    expect(lookupCidrOverlay("8.8.8.8")).toBeNull();
  });
  it("127.0.0.1 (between mobility and residential blocks) must not match", () => {
    expect(lookupCidrOverlay("127.0.0.1")).toBeNull();
  });
});

describe("lookupCidrOverlay — JS signed-int32 trap (AT&T mobility legacy 32.128.0.0/9)", () => {
  // /9 starting on a non-byte boundary — 32.128.0.0/9 = 32.128.0.0 to
  // 32.255.255.255 (NOT extending into 33.x — that was a thinko earlier).
  it("first IP of the /9 matches mobile", () => {
    expect(lookupCidrOverlay("32.128.0.0")?.category).toBe("mobile");
  });
  it("last IP of the /9 (32.255.255.255) matches mobile", () => {
    expect(lookupCidrOverlay("32.255.255.255")?.category).toBe("mobile");
  });
  it("32.127.255.255 (one below) does not match", () => {
    expect(lookupCidrOverlay("32.127.255.255")).toBeNull();
  });
  it("33.0.0.0 (one above) does not match", () => {
    expect(lookupCidrOverlay("33.0.0.0")).toBeNull();
  });
});

describe("lookupCidrOverlay — RFC 6598 CGNAT shared space (100.64.0.0/10)", () => {
  it("first IP", () => {
    expect(lookupCidrOverlay("100.64.0.0")?.category).toBe("mobile");
  });
  it("interior IP", () => {
    expect(lookupCidrOverlay("100.100.50.50")?.category).toBe("mobile");
  });
  it("last IP (100.127.255.255)", () => {
    expect(lookupCidrOverlay("100.127.255.255")?.category).toBe("mobile");
  });
  it("100.128.0.0 (one past) is not in CGNAT space", () => {
    const r = lookupCidrOverlay("100.128.0.0");
    if (r) expect(r.note).not.toContain("CGNAT");
  });
  it("100.63.255.255 (one before) is not in CGNAT space", () => {
    const r = lookupCidrOverlay("100.63.255.255");
    if (r) expect(r.note).not.toContain("CGNAT");
  });
});

describe("lookupCidrOverlay — T-Mobile /14 + /15 boundaries", () => {
  it("172.56.0.0 is mobile (start of /14)", () => {
    expect(lookupCidrOverlay("172.56.0.0")?.category).toBe("mobile");
  });
  it("172.59.255.255 is mobile (end of /14 — overlaps with /15 too)", () => {
    expect(lookupCidrOverlay("172.59.255.255")?.category).toBe("mobile");
  });
  it("172.55.255.255 (one below /14) is not in T-Mobile blocks", () => {
    expect(lookupCidrOverlay("172.55.255.255")).toBeNull();
  });
  it("172.60.0.0 (one above /14) is not in T-Mobile blocks", () => {
    expect(lookupCidrOverlay("172.60.0.0")).toBeNull();
  });
});

describe("lookupCidrOverlay — Starlink (143.105.0.0/16)", () => {
  it("143.105.0.0 — first IP — satellite", () => {
    expect(lookupCidrOverlay("143.105.0.0")?.category).toBe("satellite");
  });
  it("143.105.255.255 — last IP — satellite", () => {
    expect(lookupCidrOverlay("143.105.255.255")?.category).toBe("satellite");
  });
  it("143.106.0.0 — one past — null", () => {
    expect(lookupCidrOverlay("143.106.0.0")).toBeNull();
  });
});
