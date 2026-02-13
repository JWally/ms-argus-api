import { describe, it, expect } from "vitest";
import { resolveBrowserIdentity } from "./browser-identity";

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const FIREFOX_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";

function deviceWithUA(ua: string): Record<string, unknown> {
  return { navigator: { userAgent: ua } };
}

function deviceWithScopeUA(
  scope: "shared" | "web" | "main",
  ua: string,
): Record<string, unknown> {
  return { workerScope: { scopes: { [scope]: { userAgent: ua } } } };
}

describe("resolveBrowserIdentity", () => {
  describe("basic UA parsing", () => {
    it("should parse Chrome on Windows", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.browser).toBe("Chrome");
      expect(identity.os).toBe("Windows");
      expect(identity.deviceType).toBe("desktop");
      expect(identity.baselineKey).toBe("chrome");
      expect(identity.isWebview).toBe(false);
      expect(identity.app).toBeNull();
    });

    it("should parse Safari on iOS", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(SAFARI_IOS_UA));
      expect(identity.browser).toBe("Mobile Safari");
      expect(identity.os).toBe("iOS");
      expect(identity.deviceType).toBe("mobile");
      expect(identity.baselineKey).toBe("safari");
    });

    it("should parse Firefox", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(FIREFOX_UA));
      expect(identity.browser).toBe("Firefox");
      expect(identity.baselineKey).toBe("firefox");
    });

    it("should return unknown for empty device", () => {
      const identity = resolveBrowserIdentity({});
      expect(identity.browser).toBe("unknown");
      expect(identity.os).toBe("unknown");
      expect(identity.baselineKey).toBe("unknown");
    });

    it("should return unknown for null device", () => {
      const identity = resolveBrowserIdentity(null);
      expect(identity.browser).toBe("unknown");
    });
  });

  describe("UA extraction priority", () => {
    it("should prefer shared worker scope UA", () => {
      const device = {
        workerScope: {
          scopes: {
            shared: { userAgent: CHROME_UA },
            web: { userAgent: FIREFOX_UA },
          },
        },
        navigator: { userAgent: SAFARI_IOS_UA },
      };
      const identity = resolveBrowserIdentity(device);
      expect(identity.browser).toBe("Chrome");
    });

    it("should fall back to web scope when shared is missing", () => {
      const identity = resolveBrowserIdentity(
        deviceWithScopeUA("web", FIREFOX_UA),
      );
      expect(identity.browser).toBe("Firefox");
    });

    it("should fall back to main scope when shared/web are missing", () => {
      const identity = resolveBrowserIdentity(
        deviceWithScopeUA("main", CHROME_UA),
      );
      expect(identity.browser).toBe("Chrome");
    });

    it("should fall back to navigator when no worker scopes", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.browser).toBe("Chrome");
    });
  });

  describe("webview app detection", () => {
    it("should detect Instagram webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 302.0.0.0.0";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Instagram");
      expect(identity.isWebview).toBe(true);
      expect(identity.app).toBe("Instagram");
      expect(identity.baselineKey).toBe("instagram");
    });

    it("should detect Facebook webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/450.0.0.0;]";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Facebook");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect Gemini webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GeminiiOS/1.2.3";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Gemini");
      expect(identity.isWebview).toBe(true);
      expect(identity.browserVersion).toBe("1.2.3");
    });

    it("should detect Signal webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Signal/7.0.0";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Signal");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect Slack webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Slack/24.01.30";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Slack");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect DuckDuckGo webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) DuckDuckGo/7.88.0";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("DuckDuckGo");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect Google Search App (GSA)", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/300.0.0";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Google");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect Snapchat webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Snapchat";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Snapchat");
      expect(identity.isWebview).toBe(true);
    });

    it("should detect Pinterest webview", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Pinterest";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.browser).toBe("Pinterest");
      expect(identity.isWebview).toBe(true);
    });

    it("should not override non-generic browser names with webview detection", () => {
      // Chrome is not a generic name, so webview patterns shouldn't fire
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.isWebview).toBe(false);
      expect(identity.app).toBeNull();
    });
  });

  describe("iOS browser detection", () => {
    it("should detect CriOS as iOS browser", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.0.0 Mobile/15E148 Safari/604.1";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.isIosBrowser).toBe(true);
    });

    it("should detect FxiOS as iOS browser", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/604.1";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.isIosBrowser).toBe(true);
    });

    it("should detect EdgiOS as iOS browser", () => {
      const ua =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/120 Mobile/15E148 Safari/604.1";
      const identity = resolveBrowserIdentity(deviceWithUA(ua));
      expect(identity.isIosBrowser).toBe(true);
    });

    it("should not mark regular Chrome as iOS browser", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.isIosBrowser).toBe(false);
    });
  });

  describe("worker scope fields", () => {
    it("should extract worker scope fields", () => {
      const device = {
        navigator: { userAgent: CHROME_UA },
        workerScope: {
          userAgentEngine: "V8",
          platform: "Win32",
          userAgentVersion: "144.0.0.0",
        },
      };
      const identity = resolveBrowserIdentity(device);
      expect(identity.workerEngine).toBe("V8");
      expect(identity.workerPlatform).toBe("Win32");
      expect(identity.workerUaVersion).toBe("144.0.0.0");
    });

    it("should return null for missing worker scope", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.workerEngine).toBeNull();
      expect(identity.workerPlatform).toBeNull();
      expect(identity.workerUaVersion).toBeNull();
    });
  });

  describe("privacy state", () => {
    it("should detect private browsing", () => {
      const device = {
        navigator: { userAgent: CHROME_UA },
        incognito: { isPrivate: true },
      };
      const identity = resolveBrowserIdentity(device);
      expect(identity.isPrivate).toBe(true);
    });

    it("should default to false when no incognito field", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.isPrivate).toBe(false);
    });

    it("should return false when isPrivate is false", () => {
      const device = {
        navigator: { userAgent: CHROME_UA },
        incognito: { isPrivate: false },
      };
      const identity = resolveBrowserIdentity(device);
      expect(identity.isPrivate).toBe(false);
    });
  });

  describe("raw ua-parser-js result", () => {
    it("should include raw result", () => {
      const identity = resolveBrowserIdentity(deviceWithUA(CHROME_UA));
      expect(identity.raw).toBeDefined();
      expect(identity.raw.browser.name).toBe("Chrome");
    });
  });
});
