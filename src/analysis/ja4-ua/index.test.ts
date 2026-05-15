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
    it("shared cipher hash (a09f3c656075) does not flag either OS", () => {
      // This cipher hash is used by both iOS and macOS Safari
      const result = analyzeJa4Ua(SAFARI_IOS_SIGINT, SAFARI_MAC_UA);
      const codes = result.signals.map((s) => s.code);
      expect(codes).not.toContain("SAFARI_OS_MISMATCH");
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

  describe("TLS_UA_MISMATCH (cipher/GREASE rules in tls-rules.ts)", () => {
    // The analyzer ignores the probe's precomputed `ua_mismatch` /
    // `ua_hints` and recomputes from raw `cipher_count` / `has_grease`
    // plus the `sec-ch-ua` brand list. Rule constants live in tls-rules.ts.

    it("fires on Chromium UA with stripped TLS (8 ciphers, no GREASE)", () => {
      // Reproduces the Cisco Umbrella case. JA4 hash is unknown (Umbrella's,
      // not a browser's) so the family-table rule fails open — the cipher/
      // GREASE rules are the safety net.
      const sigint = {
        h2: {
          ja4: "t13d0800_0968ec391e9e_6d6df1345ed2",
          tls_signals: { cipher_count: 8, has_grease: false },
        },
      };
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA);
      const sig = result.signals.find((s) => s.code === "TLS_UA_MISMATCH");
      expect(sig).toBeDefined();
      expect(sig?.severity).toBe(0.7);
      expect(sig?.actual).toContain("chromium_ua_without_grease");
      expect(sig?.actual).toContain("chromium_ua_low_ciphers:8");
    });

    it("does NOT fire on stock Chrome (15 ciphers + GREASE) — FoxIO canonical baseline", () => {
      // Real-world regression. Stock Chrome 148 / Windows ships exactly 15
      // ciphers in its TLS 1.3 ClientHello (matches FoxIO JA4 spec example
      // t13d1516h2_8daaf6152771_…). Captured from session
      // 33ab1d3a-3d0f-46da-8b91-6adda535e8b0 (and 23 other sessions from
      // the same Vexus Fiber residential subscriber, all misclassified as
      // device_tampering=60 under the old threshold of 20).
      const sigint = {
        h2: {
          pseudo_header_order: "m,a,s,p",
          ja4: "t13d1516h2_8daaf6152771_f59aafdcbdd7",
          tls_signals: { cipher_count: 15, has_grease: true },
        },
      };
      const secChUa =
        '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"';
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA, secChUa);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("ignores the probe's precomputed ua_mismatch verdict — reads raw fields", () => {
      // ua_mismatch=true would have fired the OLD rule unconditionally.
      // Now we only care about cipher_count + has_grease, so a probe that
      // (incorrectly) sets ua_mismatch=true on a clean Chromium handshake
      // produces no signal.
      const sigint = {
        h2: {
          ja4: "t13d1517h2_8daaf6152771_5151127fa428",
          tls_signals: {
            ua_mismatch: true,
            ua_hints: ["chromium_ua_without_grease"],
            cipher_count: 22,
            has_grease: true,
          },
        },
      };
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("falls back to tcp_probe.tls_signals when h2 has no raw fields", () => {
      const sigint = {
        h2: { ja4: "t13d131000_aaaaaaaaaaaa_bbbbbbbbbbbb" },
        tcp_probe: {
          tls_signals: { cipher_count: 13, has_grease: false },
        },
      };
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeDefined();
    });

    it("does NOT fire when tls_signals block is missing entirely", () => {
      const result = analyzeJa4Ua(CHROME_LINUX_SIGINT, CHROME_WIN_UA);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("does NOT fire on Chromium UA with normal handshake (22 ciphers + GREASE)", () => {
      const sigint = {
        h2: {
          ja4: "t13d1517h2_8daaf6152771_5151127fa428",
          tls_signals: { cipher_count: 22, has_grease: true },
        },
      };
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("does NOT fire on Safari UA + GREASE (iOS 17+ ships GREASE)", () => {
      // Real iPhone session: GREASE + 20 ciphers. Old rule fired on
      // grease_without_known_browser_ua; new rules don't have a Safari-
      // GREASE rule at all, so it just doesn't apply.
      const sigint = {
        h2: {
          ja4: "t13d2013h2_a09f3c656075_3798386c97ff",
          tls_signals: { cipher_count: 20, has_grease: true },
        },
      };
      const result = analyzeJa4Ua(sigint, SAFARI_IOS_UA);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("fires on Safari UA with abnormally many ciphers (mitmproxy/Burp on iPhone)", () => {
      const sigint = {
        h2: {
          ja4: "t13d131000_aaaaaaaaaaaa_bbbbbbbbbbbb",
          tls_signals: { cipher_count: 35, has_grease: true },
        },
      };
      const result = analyzeJa4Ua(sigint, SAFARI_IOS_UA);
      const sig = result.signals.find((s) => s.code === "TLS_UA_MISMATCH");
      expect(sig).toBeDefined();
      expect(sig?.actual).toContain("safari_ua_high_ciphers:35");
    });

    it("Brave carve-out: does NOT fire on Chromium UA + 10 ciphers when sec-ch-ua includes Brave", () => {
      // Brave's hardened TLS stack can ship fewer ciphers than stock
      // Chrome (10 here for a value below CHROMIUM_MIN_CIPHERS). Without
      // the carve-out this would trip chromium_ua_low_ciphers:10 even
      // though sec-ch-ua correctly identifies the client as Brave.
      const sigint = {
        h2: {
          ja4: "t13d1010_0968ec391e9e_6d6df1345ed2",
          tls_signals: { cipher_count: 10, has_grease: true },
        },
      };
      const secChUa =
        '"Brave";v="1.74", "Chromium";v="146", "Not_A Brand";v="24"';
      const result = analyzeJa4Ua(sigint, CHROME_WIN_UA, secChUa);
      expect(
        result.signals.find((s) => s.code === "TLS_UA_MISMATCH"),
      ).toBeUndefined();
    });

    it("Brave carve-out does NOT mask Firefox/Safari rules", () => {
      // sec-ch-ua-brand="Brave" only suppresses the chromium-side rules.
      // A Firefox UA with > 25 ciphers must still fire even if (somehow)
      // the brand list claimed Brave.
      const sigint = {
        h2: {
          ja4: "t13d131000_aaaaaaaaaaaa_bbbbbbbbbbbb",
          tls_signals: { cipher_count: 30, has_grease: true },
        },
      };
      const secChUa = '"Brave";v="1.74", "Chromium";v="146"';
      const result = analyzeJa4Ua(sigint, FIREFOX_UA, secChUa);
      const sig = result.signals.find((s) => s.code === "TLS_UA_MISMATCH");
      expect(sig).toBeDefined();
      expect(sig?.actual).toContain("firefox_ua_high_ciphers:30");
    });

    it("fires grease_without_known_browser_ua on unknown UA + GREASE", () => {
      const sigint = {
        h2: {
          ja4: "t13d131000_aaaaaaaaaaaa_bbbbbbbbbbbb",
          tls_signals: { cipher_count: 18, has_grease: true },
        },
      };
      const result = analyzeJa4Ua(sigint, "curl/8.5.0");
      const sig = result.signals.find((s) => s.code === "TLS_UA_MISMATCH");
      expect(sig).toBeDefined();
      expect(sig?.actual).toContain("grease_without_known_browser_ua");
    });
  });
});
