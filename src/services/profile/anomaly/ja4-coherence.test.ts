import { describe, it, expect } from "vitest";
import { detectJa4Coherence } from "./ja4-coherence";
import type { Fingerprint } from "../../../types";

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
const FIREFOX_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
const SAFARI_IOS_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const SAFARI_MAC_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

function device(ua: string): Record<string, unknown> {
  return { navigator: { userAgent: ua } };
}

function fp(overrides: Partial<Fingerprint>): Fingerprint {
  return overrides as Fingerprint;
}

describe("detectJa4Coherence", () => {
  describe("early returns", () => {
    it("should return empty array when ja4 is missing", () => {
      expect(detectJa4Coherence(fp({}), device(CHROME_UA))).toEqual([]);
    });

    it("should return empty array when ja4 is unparseable", () => {
      expect(detectJa4Coherence(fp({ ja4: "bad" }), device(CHROME_UA))).toEqual(
        [],
      );
    });
  });

  describe("coherent fingerprints (no signals)", () => {
    it("should produce no signals for Chrome + BoringSSL + chromium H2", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
          h2_pseudo_header_order: "m,a,s,p",
        }),
        device(CHROME_UA),
      );
      expect(signals).toEqual([]);
    });

    it("should produce no signals for Firefox + NSS + firefox H2", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_5b57614c22b0_e5627efa2ab1",
          h2_pseudo_header_order: "m,p,a,s",
        }),
        device(FIREFOX_UA),
      );
      expect(signals).toEqual([]);
    });

    it("should produce no signals for Safari macOS + Secure Transport + apple H2", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_a09f3c656075_e5627efa2ab1",
          h2_pseudo_header_order: "m,s,p,a",
        }),
        device(SAFARI_MAC_UA),
      );
      expect(signals).toEqual([]);
    });

    it("should produce no signals for Safari iOS + Secure Transport", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_a09f3c656075_e5627efa2ab1",
          h2_pseudo_header_order: "m,s,p,a",
        }),
        device(SAFARI_IOS_UA),
      );
      expect(signals).toEqual([]);
    });
  });

  describe("TLS_PLATFORM_MISMATCH", () => {
    it("should flag Secure Transport on Windows", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_a09f3c656075_e5627efa2ab1" }),
        device(CHROME_UA), // Windows
      );
      const platform = signals.find((s) => s.code === "TLS_PLATFORM_MISMATCH");
      expect(platform).toBeDefined();
      expect(platform!.severity).toBe(0.95);
    });

    it("should not flag BoringSSL on Windows (valid)", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      const platform = signals.find((s) => s.code === "TLS_PLATFORM_MISMATCH");
      expect(platform).toBeUndefined();
    });
  });

  describe("TLS_BROWSER_MISMATCH", () => {
    it("should flag NSS (Firefox) for Chrome on Windows", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_5b57614c22b0_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      const browser = signals.find((s) => s.code === "TLS_BROWSER_MISMATCH");
      expect(browser).toBeDefined();
      expect(browser!.severity).toBe(0.9);
    });

    it("should flag BoringSSL (Chromium) for Firefox on Windows", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1" }),
        device(FIREFOX_UA),
      );
      const browser = signals.find((s) => s.code === "TLS_BROWSER_MISMATCH");
      expect(browser).toBeDefined();
    });

    it("should NOT flag on iOS (all browsers use Secure Transport)", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_a09f3c656075_e5627efa2ab1" }),
        device(SAFARI_IOS_UA),
      );
      const browser = signals.find((s) => s.code === "TLS_BROWSER_MISMATCH");
      expect(browser).toBeUndefined();
    });
  });

  describe("H2_TLS_MISMATCH", () => {
    it("should flag apple H2 with BoringSSL TLS on macOS", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
          h2_pseudo_header_order: "m,s,p,a", // apple
        }),
        device(SAFARI_MAC_UA),
      );
      const h2 = signals.find((s) => s.code === "H2_TLS_MISMATCH");
      expect(h2).toBeDefined();
      expect(h2!.severity).toBe(0.85);
    });

    it("should flag firefox H2 with BoringSSL TLS", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
          h2_pseudo_header_order: "m,p,a,s", // firefox
        }),
        device(CHROME_UA),
      );
      const h2 = signals.find((s) => s.code === "H2_TLS_MISMATCH");
      expect(h2).toBeDefined();
    });

    it("should suppress VPN pattern (QUIC + apple H2 + boringssl)", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "q13d1516h2_8daaf6152771_e5627efa2ab1", // QUIC
          h2_pseudo_header_order: "m,s,p,a", // apple
        }),
        device(CHROME_UA),
      );
      const h2 = signals.find((s) => s.code === "H2_TLS_MISMATCH");
      expect(h2).toBeUndefined();
    });

    it("should not fire for unknown H2 order", () => {
      const signals = detectJa4Coherence(
        fp({
          ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
          h2_pseudo_header_order: "a,b,c,d",
        }),
        device(CHROME_UA),
      );
      const h2 = signals.find((s) => s.code === "H2_TLS_MISMATCH");
      expect(h2).toBeUndefined();
    });
  });

  describe("QUIC_IOS_VPN", () => {
    it("should flag QUIC from claimed iOS device", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "q13d1516h2_a09f3c656075_e5627efa2ab1" }),
        device(SAFARI_IOS_UA),
      );
      const vpn = signals.find((s) => s.code === "QUIC_IOS_VPN");
      expect(vpn).toBeDefined();
      expect(vpn!.severity).toBe(0.1);
    });

    it("should not flag QUIC from Windows", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "q13d1516h2_55b375c5d22e_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      const vpn = signals.find((s) => s.code === "QUIC_IOS_VPN");
      expect(vpn).toBeUndefined();
    });

    it("should not flag TCP from iOS", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_a09f3c656075_e5627efa2ab1" }),
        device(SAFARI_IOS_UA),
      );
      const vpn = signals.find((s) => s.code === "QUIC_IOS_VPN");
      expect(vpn).toBeUndefined();
    });
  });

  describe("NO_ALPN_BROWSER", () => {
    it("should flag no ALPN (00) for Chrome", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d151600_8daaf6152771_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      const alpn = signals.find((s) => s.code === "NO_ALPN_BROWSER");
      expect(alpn).toBeDefined();
      expect(alpn!.severity).toBe(0.9);
    });

    it("should flag h1 ALPN for Firefox", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h1_5b57614c22b0_e5627efa2ab1" }),
        device(FIREFOX_UA),
      );
      const alpn = signals.find((s) => s.code === "NO_ALPN_BROWSER");
      expect(alpn).toBeDefined();
    });

    it("should not flag h2 ALPN for Chrome", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      const alpn = signals.find((s) => s.code === "NO_ALPN_BROWSER");
      expect(alpn).toBeUndefined();
    });

    it("should not flag no ALPN for unknown browser", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d151600_8daaf6152771_e5627efa2ab1" }),
        {},
      );
      const alpn = signals.find((s) => s.code === "NO_ALPN_BROWSER");
      expect(alpn).toBeUndefined();
    });
  });

  describe("unknown cipher hash", () => {
    it("should still check ALPN and QUIC rules for unknown hashes", () => {
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d151600_000000000000_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      // Should not have TLS stack checks but should have ALPN check
      expect(
        signals.find((s) => s.code === "TLS_PLATFORM_MISMATCH"),
      ).toBeUndefined();
      expect(signals.find((s) => s.code === "NO_ALPN_BROWSER")).toBeDefined();
    });
  });

  describe("multiple signals", () => {
    it("should produce multiple signals for badly spoofed fingerprint", () => {
      // Secure Transport (Apple-only) + Chrome UA on Windows + no ALPN
      const signals = detectJa4Coherence(
        fp({ ja4: "t13d151600_a09f3c656075_e5627efa2ab1" }),
        device(CHROME_UA),
      );
      expect(signals.length).toBeGreaterThanOrEqual(2);
      const codes = signals.map((s) => s.code);
      expect(codes).toContain("TLS_PLATFORM_MISMATCH");
      expect(codes).toContain("NO_ALPN_BROWSER");
    });
  });
});
