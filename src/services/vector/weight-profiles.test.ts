import { describe, it, expect } from "vitest";
import { getWeightProfile } from "./weight-profiles";
import type { OsCategory } from "./os-detection";

const ALL_OS: OsCategory[] = ["ios", "android", "windows", "mac", "linux"];

describe("getWeightProfile", () => {
  it.each(ALL_OS)("returns 512-dim weights for %s", (os) => {
    const profile = getWeightProfile(os);
    expect(profile.weights).toHaveLength(512);
  });

  it.each(ALL_OS)("returns a numeric threshold for %s", (os) => {
    const profile = getWeightProfile(os);
    expect(profile.threshold).toBeGreaterThan(0);
    expect(profile.threshold).toBeLessThanOrEqual(1);
  });

  it("linux weights are all 1.0 (baseline)", () => {
    const { weights } = getWeightProfile("linux");
    expect(weights.every((w) => w === 1.0)).toBe(true);
  });

  it("iOS zeroes canvas_198 (dim 198)", () => {
    const { weights } = getWeightProfile("ios");
    expect(weights[198]).toBe(0);
  });

  it("iOS boosts user_agent section (dims 294-309)", () => {
    const { weights } = getWeightProfile("ios");
    expect(weights[294]).toBeGreaterThan(4);
    expect(weights[309]).toBeGreaterThan(4);
  });

  it("Android zeroes htmlElement section (dims 135-158)", () => {
    const { weights } = getWeightProfile("android");
    expect(weights[135]).toBe(0);
    expect(weights[158]).toBe(0);
  });

  it("Windows boosts screen_dims section (dims 270-285)", () => {
    const { weights } = getWeightProfile("windows");
    expect(weights[270]).toBeGreaterThan(4);
  });

  it("Windows zeroes cssMedia section (dims 0-67)", () => {
    const { weights } = getWeightProfile("windows");
    expect(weights[0]).toBe(0);
    expect(weights[67]).toBe(0);
  });

  it("Mac boosts svg section (dims 175-182)", () => {
    const { weights } = getWeightProfile("mac");
    expect(weights[175]).toBe(5.0);
  });

  it("each OS has distinct weights (not all identical)", () => {
    const profiles = ALL_OS.map((os) => getWeightProfile(os).weights);
    // Compare each pair
    for (let i = 0; i < profiles.length; i++) {
      for (let j = i + 1; j < profiles.length; j++) {
        const same = profiles[i].every((v, k) => v === profiles[j][k]);
        expect(same).toBe(false);
      }
    }
  });

  it("all weights are non-negative", () => {
    for (const os of ALL_OS) {
      const { weights } = getWeightProfile(os);
      expect(weights.every((w) => w >= 0)).toBe(true);
    }
  });
});
