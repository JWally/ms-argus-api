import { describe, expect, it } from "vitest";
import { Hll, HLL_SERIALIZED_BYTES } from "./hll";

describe("Hll", () => {
  it("counts zero on empty", () => {
    expect(new Hll().count()).toBe(0);
  });

  it("counts exact small cardinality via linear counting", () => {
    const h = new Hll();
    for (let i = 0; i < 8; i++) h.add(`device-${i}`);
    // Linear-counting region: should be effectively exact (off by ≤1).
    const c = h.count();
    expect(Math.abs(c - 8)).toBeLessThanOrEqual(1);
  });

  it("is idempotent — re-adding same id doesn't tick count", () => {
    const h = new Hll();
    for (let i = 0; i < 5; i++) h.add("same-device");
    expect(h.count()).toBe(1);
  });

  it("is within ±5% of true count at moderate cardinality", () => {
    const h = new Hll();
    const N = 5000;
    for (let i = 0; i < N; i++) h.add(`device-${i}`);
    const c = h.count();
    expect(c).toBeGreaterThan(N * 0.95);
    expect(c).toBeLessThan(N * 1.05);
  });

  it("serializes round-trip", () => {
    const a = new Hll();
    for (let i = 0; i < 100; i++) a.add(`d-${i}`);
    const bytes = a.toBytes();
    expect(bytes.length).toBe(HLL_SERIALIZED_BYTES);
    const b = Hll.fromBytes(bytes);
    expect(b.count()).toBe(a.count());
  });

  it("merges register-wise — union cardinality is correct", () => {
    const a = new Hll();
    const b = new Hll();
    for (let i = 0; i < 1000; i++) a.add(`a-${i}`);
    for (let i = 0; i < 1000; i++) b.add(`b-${i}`);
    // Disjoint sets — merged should be ~2000.
    a.merge(b);
    expect(a.count()).toBeGreaterThan(1900);
    expect(a.count()).toBeLessThan(2100);
  });

  it("merge handles overlap correctly", () => {
    const a = new Hll();
    const b = new Hll();
    for (let i = 0; i < 1000; i++) a.add(`shared-${i}`);
    for (let i = 0; i < 1000; i++) b.add(`shared-${i}`); // same set
    a.merge(b);
    // Union of identical sets is the same set.
    expect(a.count()).toBeGreaterThan(950);
    expect(a.count()).toBeLessThan(1050);
  });

  it("rejects mismatched byte length", () => {
    expect(() => Hll.fromBytes(Buffer.alloc(100))).toThrow();
  });

  it("rejects mismatched version", () => {
    const bytes = new Hll().toBytes();
    bytes[0] = 99;
    expect(() => Hll.fromBytes(bytes)).toThrow();
  });
});
