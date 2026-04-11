import { describe, it, expect } from "vitest";
import { analyzeJa4Ua } from "./index";

// Real signatures from observed traffic (2026-04)
const CHROME_LINUX_SIGINT = {
  h2: {
    ja4: "t13d1517h2_8daaf6152771_5151127fa428",
    pseudo_header_order: "m,a,s,p",
  },
  tcp_probe: {
    ja4: "t13d1517h2_8daaf6152771_5151127fa428",
  },
};

const SAFARI_IOS_SIGINT = {
  h2: {
    ja4: "t13d2013h2_a09f3c656075_3798386c97ff",
    pseudo_header_order: "m,s,a,p",
  },
  tcp_probe: {
    ja4: "t13d2013h2_a09f3c656075_3798386c97ff",
  },
};

const SAFARI_MAC_SIGINT = {
  h2: {
    ja4: "t13d2913h2_723694b0fccc_23bb5c11ba0e",
    pseudo_header_order: "m,s,a,p",
  },
  tcp_probe: {
    ja4: "t13d2913h2_723694b0fccc_23bb5c11ba0e",
  },
};

const FIREFOX_SIGINT = {
  h2: {
    ja4: "t13d1717h2_5b57614c22b0_e7cb5e303734",
    pseudo_header_order: "m,p,a,s",
  },
  tcp_probe: {
    ja4: "t13d1717h2_5b57614c22b0_e7cb5e303734",
  },
};

const CHROME_WIN_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const _CHROME_LINUX_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1";
const SAFARI_MAC_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
const FIREFOX_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

describe("analyzeJa4Ua", () => {
  describe("matching signals (no anomalies)", () => {
    it("Chrome sigint + Chrome UA", () => {
      const result = analyzeJa4Ua(CHROME_LINUX_SIGINT, CHROME_WIN_UA);
      expect(result.ja4_browser_family).toBe("chromium");
      expect(result.h2_browser_family).toBe("chromium");
      expect(result.ua_browser_family).toBe("chromium");
      expect(result.signals).toHaveLength(0);
    });

    it("Safari iOS sigint + Safari iOS UA", () => {
      const result = analyzeJa4Ua(SAFARI_IOS_SIGINT, SAFARI_IOS_UA);
      expect(result.ja4_browser_family).toBe("safari");
      expect(result.h2_browser_family).toBe("safari");
      expect(result.ua_browser_family).toBe("safari");
      expect(result.signals).toHaveLength(0);
    });

    it("Safari macOS sigint + Safari macOS UA", () => {
      const result = analyzeJa4Ua(SAFARI_MAC_SIGINT, SAFARI_MAC_UA);
      expect(result.signals).toHaveLength(0);
    });

    it("Firefox sigint + Firefox UA", () => {
      const result = analyzeJa4Ua(FIREFOX_SIGINT, FIREFOX_UA);
      expect(result.ja4_browser_family).toBe("firefox");
      expect(result.h2_browser_family).toBe("firefox");
      expect(result.ua_browser_family).toBe("firefox");
      expect(result.signals).toHaveLength(0);
    });
  });

  describe("browser family mismatches", () => {
    it("Chrome TLS + Firefox UA", () => {
      const result = analyzeJa4Ua(CHROME_LINUX_SIGINT, FIREFOX_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).toContain("JA4_UA_BROWSER_MISMATCH");
      expect(codes).toContain("H2_UA_BROWSER_MISMATCH");
    });

    it("Firefox TLS + Chrome UA", () => {
      const result = analyzeJa4Ua(FIREFOX_SIGINT, CHROME_WIN_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).toContain("JA4_UA_BROWSER_MISMATCH");
      expect(codes).toContain("H2_UA_BROWSER_MISMATCH");
    });

    it("Safari TLS + Chrome UA", () => {
      const result = analyzeJa4Ua(SAFARI_IOS_SIGINT, CHROME_WIN_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).toContain("JA4_UA_BROWSER_MISMATCH");
      expect(codes).toContain("H2_UA_BROWSER_MISMATCH");
    });
  });

  describe("Safari OS mismatch", () => {
    it("iOS cipher hash + macOS UA", () => {
      const result = analyzeJa4Ua(SAFARI_IOS_SIGINT, SAFARI_MAC_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).toContain("SAFARI_OS_MISMATCH");
      expect(
        result.signals.find((s) => s.code === "SAFARI_OS_MISMATCH")?.expected,
      ).toBe("Safari TLS cipher → iOS");
    });

    it("macOS cipher hash + iOS UA", () => {
      const result = analyzeJa4Ua(SAFARI_MAC_SIGINT, SAFARI_IOS_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).toContain("SAFARI_OS_MISMATCH");
    });
  });

  describe("iOS alternate browsers (CriOS/FxiOS)", () => {
    it("Chrome on iOS uses Safari TLS — no mismatch", () => {
      const criosUA =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1";
      const result = analyzeJa4Ua(SAFARI_IOS_SIGINT, criosUA);
      // CriOS maps to safari family (uses Apple TLS), so no browser mismatch
      expect(result.ua_browser_family).toBe("safari");
      expect(
        result.signals.filter((s) => s.code === "JA4_UA_BROWSER_MISMATCH"),
      ).toHaveLength(0);
    });
  });

  describe("missing data", () => {
    it("no sigint — returns families from UA only", () => {
      const result = analyzeJa4Ua(null, CHROME_WIN_UA);
      expect(result.ja4_browser_family).toBeNull();
      expect(result.h2_browser_family).toBeNull();
      expect(result.ua_browser_family).toBe("chromium");
      expect(result.signals).toHaveLength(0);
    });

    it("no UA — no signals", () => {
      const result = analyzeJa4Ua(CHROME_LINUX_SIGINT, "");
      expect(result.ja4_browser_family).toBe("chromium");
      expect(result.ua_browser_family).toBeNull();
      expect(result.signals).toHaveLength(0);
    });

    it("unknown cipher hash — no JA4 family", () => {
      const sigint = {
        h2: {
          ja4: "t13d131000_0968ec391e9e_6d6df1345ed2",
          pseudo_header_order: "m,a,s,p",
        },
      };
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA);
      expect(result.ja4_browser_family).toBeNull();
      expect(result.h2_browser_family).toBe("chromium");
      expect(result.signals).toHaveLength(0);
    });
  });
});
