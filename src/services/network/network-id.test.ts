import { describe, it, expect } from "vitest";
import { deriveNetworkId, normalizeUa, ipv4To24 } from "./network-id";

const RES_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Chrome/126.0.6478.127 Safari/605.1.15";

describe("normalizeUa", () => {
  it("collapses Chrome minor build version", () => {
    expect(normalizeUa(RES_UA)).toContain("Chrome/126");
    expect(normalizeUa(RES_UA)).not.toContain("126.0.6478.127");
  });

  it("collapses iOS version", () => {
    const ua =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) Version/17.5";
    const norm = normalizeUa(ua);
    expect(norm).toContain("CPU iPhone OS 17 like");
    expect(norm).toContain("Version/17");
  });

  it("collapses Android version", () => {
    expect(normalizeUa("(Linux; Android 14.0.0)")).toContain("Android 14");
  });

  it("collapses Windows NT version", () => {
    expect(normalizeUa("Windows NT 10.0; Win64")).toContain("Windows NT;");
  });
});

describe("ipv4To24", () => {
  it("drops the last octet", () => {
    expect(ipv4To24("107.210.133.127")).toBe("107.210.133.0/24");
  });

  it("rejects malformed input", () => {
    expect(ipv4To24("nope")).toBeNull();
    expect(ipv4To24("1.2.3")).toBeNull();
    expect(ipv4To24("256.0.0.1")).toBeNull();
  });
});

describe("deriveNetworkId — Pass 1 (recognized class)", () => {
  it("residential: emits stable category-residential ID", () => {
    const out = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: RES_UA,
    });
    expect(out.source).toBe("category_residential");
    expect(out.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it("residential: same /24 + same UA → same ID", () => {
    const a = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: RES_UA,
    });
    const b = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.99", // same /24
      userAgent: RES_UA,
    });
    expect(a.id).toBe(b.id);
  });

  it("residential: different /24 → different ID", () => {
    const a = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: RES_UA,
    });
    const b = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.99.5.10",
      userAgent: RES_UA,
    });
    expect(a.id).not.toBe(b.id);
  });

  it("residential: build-version refresh within same major doesn't change ID", () => {
    const ua1 = RES_UA;
    // Same major (126), different build (.127 → .183) — typical Chrome
    // intra-major auto-update over a few weeks.
    const ua2 = RES_UA.replace("126.0.6478.127", "126.0.6478.183");
    const a = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: ua1,
    });
    const b = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: ua2,
    });
    expect(a.id).toBe(b.id);
  });

  it("residential: major-version bump DOES change ID (intentional churn)", () => {
    const ua1 = RES_UA;
    const ua2 = RES_UA.replace("126.0.6478.127", "127.0.0.0");
    const a = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: ua1,
    });
    const b = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: ua2,
    });
    expect(a.id).not.toBe(b.id);
  });

  it("satellite (Starlink): treated as residential", () => {
    const out = deriveNetworkId({
      asn: 14593,
      networkClass: "satellite",
      ip: "143.105.85.139",
      userAgent: RES_UA,
    });
    expect(out.source).toBe("category_residential");
    expect(out.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it.each<NonNullable<Parameters<typeof deriveNetworkId>[0]["networkClass"]>>([
    "mobile",
    "vpn_proxy",
    "hosting_proxy",
    "datacenter",
    "cdn",
    "privacy_relay",
    "business",
    "security_filter",
    "education",
    "government",
  ])("non-residential class %s → null", (cls) => {
    const out = deriveNetworkId({
      asn: 16509,
      networkClass: cls,
      ip: "1.2.3.4",
      userAgent: RES_UA,
    });
    expect(out.id).toBeNull();
    expect(out.source).toBe("none");
  });
});

describe("deriveNetworkId — Pass 2 (unrecognized ASN)", () => {
  it("unknown class with ASN → asn_fallback ID", () => {
    const out = deriveNetworkId({
      asn: 207044,
      networkClass: "unknown",
      ip: "89.184.63.240",
      userAgent: RES_UA,
    });
    expect(out.source).toBe("asn_fallback");
    expect(out.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it("null networkClass with ASN → asn_fallback", () => {
    const out = deriveNetworkId({
      asn: 207044,
      networkClass: null,
      ip: "89.184.63.240",
      userAgent: RES_UA,
    });
    expect(out.source).toBe("asn_fallback");
    expect(out.id).toMatch(/^[0-9a-f]{16}$/);
  });

  it("unknown ASN: different ASN → different ID even with same IP", () => {
    const a = deriveNetworkId({
      asn: 207044,
      networkClass: null,
      ip: "1.2.3.4",
      userAgent: RES_UA,
    });
    const b = deriveNetworkId({
      asn: 999999,
      networkClass: null,
      ip: "1.2.3.4",
      userAgent: RES_UA,
    });
    expect(a.id).not.toBe(b.id);
  });

  it("no ASN and unknown class → none", () => {
    const out = deriveNetworkId({
      asn: null,
      networkClass: null,
      ip: "1.2.3.4",
      userAgent: RES_UA,
    });
    expect(out.id).toBeNull();
    expect(out.source).toBe("none");
  });
});

describe("deriveNetworkId — guards", () => {
  it("missing IP → none", () => {
    const out = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: null,
      userAgent: RES_UA,
    });
    expect(out.id).toBeNull();
  });

  it("missing UA → none", () => {
    const out = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "73.43.1.77",
      userAgent: null,
    });
    expect(out.id).toBeNull();
  });

  it("malformed IP → none", () => {
    const out = deriveNetworkId({
      asn: 7922,
      networkClass: "residential",
      ip: "not-an-ip",
      userAgent: RES_UA,
    });
    expect(out.id).toBeNull();
  });
});
