import { describe, it, expect } from "vitest";
import { parseUaToBrowser } from "./ua-parser";

const CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
const EDGE =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0";
const EDGE_IOS =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 EdgiOS/147.0";
const FIREFOX =
  "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0";
const FIREFOX_IOS =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 FxiOS/130.0";
const CHROME_IOS =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 CriOS/147.0";
const SAFARI_IOS =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1";
const SAFARI_MAC =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

describe("parseUaToBrowser", () => {
  it("returns null when ua is missing", () => {
    expect(parseUaToBrowser(null, null)).toBeNull();
    expect(parseUaToBrowser("", null)).toBeNull();
  });

  it("recognizes Chrome on desktop", () => {
    const r = parseUaToBrowser(CHROME, null);
    expect(r).toEqual({
      browser: "Chrome",
      version: "147",
      engineFamily: "chromium",
    });
  });

  it("recognizes Edge BEFORE Chrome (UA contains both tokens)", () => {
    const r = parseUaToBrowser(EDGE, null);
    expect(r?.browser).toBe("Edge");
    expect(r?.engineFamily).toBe("chromium");
  });

  it("recognizes EdgiOS variant", () => {
    expect(parseUaToBrowser(EDGE_IOS, null)?.browser).toBe("Edge");
  });

  it("recognizes Firefox proper as gecko", () => {
    const r = parseUaToBrowser(FIREFOX, null);
    expect(r).toEqual({
      browser: "Firefox",
      version: "149",
      engineFamily: "gecko",
    });
  });

  it("recognizes Firefox-iOS as webkit (App Store rule)", () => {
    const r = parseUaToBrowser(FIREFOX_IOS, null);
    expect(r?.browser).toBe("Firefox iOS");
    expect(r?.engineFamily).toBe("webkit");
  });

  it("recognizes Chrome-iOS as webkit (App Store rule)", () => {
    const r = parseUaToBrowser(CHROME_IOS, null);
    expect(r?.browser).toBe("Chrome iOS");
    expect(r?.engineFamily).toBe("webkit");
  });

  it("recognizes Safari on iOS via Version/N", () => {
    const r = parseUaToBrowser(SAFARI_IOS, null);
    expect(r?.browser).toBe("Safari iOS");
    expect(r?.version).toBe("26.0");
    expect(r?.engineFamily).toBe("webkit");
  });

  it("recognizes Safari on macOS via Version/N (covers the macOS branch)", () => {
    const r = parseUaToBrowser(SAFARI_MAC, null);
    expect(r?.browser).toBe("Safari macOS");
    expect(r?.version).toBe("17.5");
    expect(r?.engineFamily).toBe("webkit");
  });

  it("returns Safari iOS with '?' version when Version/N is absent", () => {
    const ua =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari/604.1";
    const r = parseUaToBrowser(ua, null);
    expect(r?.browser).toBe("Safari iOS");
    expect(r?.version).toBe("?");
  });

  it("returns Safari macOS with '?' version when Version/N is absent", () => {
    const ua =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15";
    const r = parseUaToBrowser(ua, null);
    expect(r?.browser).toBe("Safari macOS");
    expect(r?.version).toBe("?");
  });

  it("returns null for an unknown UA", () => {
    expect(parseUaToBrowser("Wget/1.21.4", null)).toBeNull();
  });

  it("recognizes Brave via sec-ch-ua brand list (UA hides as Chrome)", () => {
    const secChUa = '"Brave";v="147", "Chromium";v="147", "Not?A_Brand";v="99"';
    const r = parseUaToBrowser(CHROME, secChUa);
    expect(r?.browser).toBe("Brave");
    expect(r?.version).toBe("147");
    expect(r?.engineFamily).toBe("chromium");
  });

  it("Brave returns '?' version when sec-ch-ua lists Brave but no version", () => {
    const r = parseUaToBrowser(CHROME, '"Brave"');
    expect(r?.browser).toBe("Brave");
    expect(r?.version).toBe("?");
  });

  it("ignores sec-ch-ua without a Brave brand", () => {
    const secChUa = '"Chromium";v="147", "Not?A_Brand";v="99"';
    const r = parseUaToBrowser(CHROME, secChUa);
    expect(r?.browser).toBe("Chrome");
  });
});
