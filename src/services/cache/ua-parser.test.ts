import { describe, it, expect } from "vitest";
import { extractUaFamily } from "./ua-parser";

describe("extractUaFamily", () => {
  it("should detect Chrome", () => {
    const ua =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    expect(extractUaFamily(ua)).toBe("Chrome");
  });

  it("should detect Firefox", () => {
    const ua =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
    expect(extractUaFamily(ua)).toBe("Firefox");
  });

  it("should detect Safari (no Chrome in UA)", () => {
    // Real Safari doesn't have Chrome in UA string
    const ua =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
    expect(extractUaFamily(ua)).toBe("Safari");
  });

  it("should detect Chrome even when Safari is in UA", () => {
    // Chrome on Mac has both Chrome and Safari
    const ua =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    expect(extractUaFamily(ua)).toBe("Chrome");
  });

  it("should detect Edge (contains Chrome)", () => {
    const ua =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    expect(extractUaFamily(ua)).toBe("Edge");
  });

  it("should detect Opera (contains Chrome)", () => {
    const ua =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0";
    expect(extractUaFamily(ua)).toBe("Opera");
  });

  it("should detect IE", () => {
    const ua =
      "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)";
    expect(extractUaFamily(ua)).toBe("IE");
  });

  it("should detect IE via Trident", () => {
    const ua = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
    expect(extractUaFamily(ua)).toBe("IE");
  });

  it("should detect Samsung Browser", () => {
    const ua =
      "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36";
    expect(extractUaFamily(ua)).toBe("Samsung");
  });

  it("should detect UC Browser", () => {
    const ua =
      "Mozilla/5.0 (Linux; U; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) UCBrowser/13.4.0.1306 Mobile Safari/537.36";
    expect(extractUaFamily(ua)).toBe("UC");
  });

  it("should return Unknown for empty string", () => {
    expect(extractUaFamily("")).toBe("Unknown");
  });

  it("should return Unknown for undefined", () => {
    expect(extractUaFamily(undefined)).toBe("Unknown");
  });

  it("should return Unknown for unrecognized UA", () => {
    expect(extractUaFamily("SomeCustomBot/1.0")).toBe("Unknown");
  });
});
