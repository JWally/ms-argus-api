import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  lookupAutoOverlaySync,
  _resetAutoOverlayForTesting,
  _seedAutoOverlayForTesting,
} from "./auto-overlay";

beforeEach(() => _resetAutoOverlayForTesting());
afterEach(() => _resetAutoOverlayForTesting());

describe("auto-overlay sync lookup", () => {
  it("returns null when not seeded (empty cache)", () => {
    expect(lookupAutoOverlaySync("8.8.8.8")).toBeNull();
  });

  it("returns category + name when IP is in a seeded rule", () => {
    _seedAutoOverlayForTesting([
      { cidr: "203.0.113.0/24", category: "residential", name: "TEST-NET-3" },
    ]);
    expect(lookupAutoOverlaySync("203.0.113.42")).toEqual({
      category: "residential",
      name: "TEST-NET-3",
    });
  });

  it("returns null for IPs outside seeded rules", () => {
    _seedAutoOverlayForTesting([
      { cidr: "203.0.113.0/24", category: "residential", name: "TEST-NET-3" },
    ]);
    expect(lookupAutoOverlaySync("8.8.8.8")).toBeNull();
  });

  it("handles multiple rules + boundary checks", () => {
    _seedAutoOverlayForTesting([
      { cidr: "10.0.0.0/8", category: "residential", name: "BLOCK-A" },
      { cidr: "100.64.0.0/10", category: "mobile", name: "CGNAT" },
      { cidr: "143.105.0.0/16", category: "satellite", name: "STARLINK" },
    ]);
    expect(lookupAutoOverlaySync("10.255.255.255")?.name).toBe("BLOCK-A");
    expect(lookupAutoOverlaySync("11.0.0.0")).toBeNull();
    expect(lookupAutoOverlaySync("100.127.255.255")?.category).toBe("mobile");
    expect(lookupAutoOverlaySync("143.105.50.50")?.category).toBe("satellite");
  });

  it("survives malformed IPs without throwing", () => {
    _seedAutoOverlayForTesting([
      { cidr: "8.8.8.0/24", category: "datacenter", name: "GOOG" },
    ]);
    expect(lookupAutoOverlaySync("not-an-ip")).toBeNull();
    expect(lookupAutoOverlaySync("1.2.3")).toBeNull();
  });
});

describe("auto-overlay reset hook", () => {
  it("clears state so next lookup hits the cold-start path", () => {
    _seedAutoOverlayForTesting([
      { cidr: "192.0.2.0/24", category: "residential", name: "TEST-NET-1" },
    ]);
    expect(lookupAutoOverlaySync("192.0.2.5")).not.toBeNull();
    _resetAutoOverlayForTesting();
    // After reset, sync lookup returns null until seed/load
    expect(lookupAutoOverlaySync("192.0.2.5")).toBeNull();
  });
});
