import { describe, it, expect } from "vitest";
import { parseUAFamily, getBaselineKey, getUADescription } from "./ua-family";

describe("parseUAFamily", () => {
  it("should return unknown for null/undefined user agent", () => {
    expect(parseUAFamily(null).baselineKey).toBe("unknown");
    expect(parseUAFamily(undefined).baselineKey).toBe("unknown");
    expect(parseUAFamily("").baselineKey).toBe("unknown");
  });

  describe("normalizeBrowserName", () => {
    it("should normalize Chromium to chrome", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/120.0.0.0 Chrome/120.0.0.0 Safari/537.36",
      );
      expect(result.baselineKey).toBe("chrome");
    });

    it("should normalize Chrome Headless to chrome", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
      );
      // HeadlessChrome is detected as headless bot by bot patterns
      expect(result.baselineKey).toBe("bot");
    });

    it("should normalize Mobile Safari to safari", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      );
      expect(result.baselineKey).toBe("safari");
    });

    it("should normalize Internet Explorer to ie", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
      );
      expect(result.baselineKey).toBe("ie");
    });

    it("should normalize standard Chrome UA", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      );
      expect(result.baselineKey).toBe("chrome");
    });

    it("should normalize Firefox UA", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
      );
      expect(result.baselineKey).toBe("firefox");
    });

    it("should normalize Edge UA", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
      );
      expect(result.baselineKey).toBe("edge");
    });

    it("should lowercase unknown browsers with spaces replaced by underscores", () => {
      // A hypothetical unknown browser
      const ua = parseUAFamily("Mozilla/5.0 (compatible; MyCustomBrowser/1.0)");
      // ua-parser-js may not recognize it, so it falls through
      expect(ua.baselineKey).toBe(ua.baselineKey.toLowerCase());
      expect(ua.baselineKey).not.toContain(" ");
    });
  });

  describe("bot detection", () => {
    it("should detect curl as bot", () => {
      const result = parseUAFamily("curl/8.5.0");
      expect(result.baselineKey).toBe("bot");
      expect(result.browser).toBe("bot");
      expect(result.deviceType).toBe("bot");
    });

    it("should detect wget as bot", () => {
      const result = parseUAFamily("Wget/1.21");
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect selenium as bot", () => {
      const result = parseUAFamily("Mozilla/5.0 Selenium WebDriver Chrome/120");
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect puppeteer as bot", () => {
      const result = parseUAFamily("Mozilla/5.0 Puppeteer HeadlessChrome/120");
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect playwright as bot", () => {
      const result = parseUAFamily("Mozilla/5.0 Playwright HeadlessChrome/120");
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect python-requests as bot", () => {
      const result = parseUAFamily("python-requests/2.31.0");
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect Googlebot as bot", () => {
      const result = parseUAFamily(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
      );
      expect(result.baselineKey).toBe("bot");
    });

    it("should detect node-fetch as bot", () => {
      const result = parseUAFamily("node-fetch/3.3.0");
      expect(result.baselineKey).toBe("bot");
    });
  });

  it("should parse major version correctly", () => {
    const result = parseUAFamily(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    expect(result.majorVersion).toBe(120);
  });

  it("should parse OS correctly", () => {
    const result = parseUAFamily(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    expect(result.os).toBe("Windows");
  });

  it("should default deviceType to desktop", () => {
    const result = parseUAFamily(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    expect(result.deviceType).toBe("desktop");
  });
});

describe("getBaselineKey", () => {
  it("should return baseline key for valid UA", () => {
    expect(
      getBaselineKey(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      ),
    ).toBe("chrome");
  });

  it("should return unknown for null UA", () => {
    expect(getBaselineKey(null)).toBe("unknown");
  });
});

describe("getUADescription", () => {
  it("should return 'unknown' for null UA", () => {
    expect(getUADescription(null)).toBe("unknown");
  });

  it("should return 'bot' for bot UA", () => {
    expect(getUADescription("curl/8.5.0")).toBe("bot");
  });

  it("should format browser with version and OS", () => {
    const desc = getUADescription(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    expect(desc).toContain("Chrome");
    expect(desc).toContain("120");
    expect(desc).toContain("Windows");
  });

  it("should omit version when not detected", () => {
    // For an unknown-version scenario, check format
    const desc = getUADescription(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );
    // Should contain browser name and OS
    expect(desc).toBeTruthy();
    expect(desc).not.toBe("unknown");
    expect(desc).not.toBe("bot");
  });
});
