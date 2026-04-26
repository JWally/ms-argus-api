import { describe, it, expect } from "vitest";
import {
  ipToInt,
  intToIp,
  cidrToRange,
  compileCidrList,
  lookupInRanges,
} from "./cidr-tree";

describe("ipToInt / intToIp", () => {
  it("round-trips dotted-quad to uint32 and back", () => {
    for (const ip of [
      "0.0.0.0",
      "10.0.0.1",
      "127.0.0.1",
      "192.168.1.1",
      "255.255.255.255",
    ]) {
      expect(intToIp(ipToInt(ip))).toBe(ip);
    }
  });

  it("returns unsigned uint32 for high IPs (signed-int32 trap)", () => {
    // 174.193.0.1 was the regression case — must not be negative
    expect(ipToInt("174.193.0.1")).toBeGreaterThan(0);
    expect(ipToInt("255.255.255.255")).toBe(0xffffffff);
  });

  it("returns NaN for malformed input", () => {
    expect(Number.isNaN(ipToInt("not-an-ip"))).toBe(true);
  });
});

describe("cidrToRange", () => {
  it("/10 covers ~4M IPs", () => {
    const r = cidrToRange("107.64.0.0/10");
    expect(r).not.toBeNull();
    const [start, end] = r!;
    expect(end - start + 1).toBe(4_194_304);
    expect(intToIp(start)).toBe("107.64.0.0");
    expect(intToIp(end)).toBe("107.127.255.255");
  });

  it("/32 is a single IP", () => {
    const r = cidrToRange("8.8.8.8/32");
    expect(r).toEqual([ipToInt("8.8.8.8"), ipToInt("8.8.8.8")]);
  });

  it("/0 covers all of IPv4", () => {
    const r = cidrToRange("0.0.0.0/0");
    expect(r).toEqual([0, 0xffffffff]);
  });

  it("normalizes non-aligned CIDRs to the canonical block", () => {
    // 107.64.5.5/10 should normalize to 107.64.0.0/10
    const aligned = cidrToRange("107.64.0.0/10");
    const fuzzy = cidrToRange("107.64.5.5/10");
    expect(aligned).toEqual(fuzzy);
  });

  it("returns null for malformed input", () => {
    expect(cidrToRange("nope")).toBeNull();
    expect(cidrToRange("8.8.8.8")).toBeNull();
    expect(cidrToRange("8.8.8.8/33")).toBeNull();
    expect(cidrToRange("8.8.8.8/-1")).toBeNull();
  });
});

describe("lookupInRanges", () => {
  const ranges = compileCidrList([
    {
      cidr: "10.0.0.0/8",
      category: "residential",
      meta: { name: "RFC1918-A" },
    },
    {
      cidr: "100.64.0.0/10",
      category: "mobile",
      meta: { name: "RFC6598-CGNAT" },
    },
    {
      cidr: "107.64.0.0/10",
      category: "mobile",
      meta: { name: "ATT-MOBILITY" },
    },
    {
      cidr: "143.105.0.0/16",
      category: "satellite",
      meta: { name: "STARLINK" },
    },
    { cidr: "174.192.0.0/9", category: "mobile", meta: { name: "VZW" } },
  ]);

  it("hits inside a range", () => {
    expect(lookupInRanges(ranges, "107.116.185.73")?.category).toBe("mobile");
    expect(lookupInRanges(ranges, "143.105.50.50")?.category).toBe("satellite");
  });

  it("hits at exact range boundaries", () => {
    expect(lookupInRanges(ranges, "107.64.0.0")?.category).toBe("mobile");
    expect(lookupInRanges(ranges, "107.127.255.255")?.category).toBe("mobile");
  });

  it("misses one IP past the end of a range", () => {
    expect(lookupInRanges(ranges, "107.128.0.0")).toBeNull();
  });

  it("VZW /9 boundary check (signed-int32 regression)", () => {
    expect(lookupInRanges(ranges, "174.193.0.1")?.category).toBe("mobile");
    expect(lookupInRanges(ranges, "174.255.255.255")?.category).toBe("mobile");
  });

  it("8.8.8.8 must not spuriously match anything", () => {
    expect(lookupInRanges(ranges, "8.8.8.8")).toBeNull();
  });

  it("returns null for malformed input", () => {
    expect(lookupInRanges(ranges, "not-an-ip")).toBeNull();
    expect(lookupInRanges(ranges, "1.2.3")).toBeNull();
  });

  it("preserves meta on hit", () => {
    const hit = lookupInRanges(ranges, "107.116.185.73");
    expect(hit?.meta).toEqual({ name: "ATT-MOBILITY" });
  });
});

describe("compileCidrList", () => {
  it("drops malformed CIDRs without throwing", () => {
    const r = compileCidrList([
      { cidr: "8.8.8.0/24", category: "datacenter" },
      { cidr: "garbage", category: "mobile" },
      { cidr: "1.1.1.0/24", category: "cdn" },
    ]);
    expect(r.length).toBe(2);
  });

  it("returns ranges sorted by start", () => {
    const r = compileCidrList([
      { cidr: "200.0.0.0/8", category: "residential" },
      { cidr: "10.0.0.0/8", category: "residential" },
      { cidr: "100.0.0.0/8", category: "residential" },
    ]);
    expect(r[0].start).toBeLessThan(r[1].start);
    expect(r[1].start).toBeLessThan(r[2].start);
  });
});
