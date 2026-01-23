import { describe, it, expect } from "vitest";
import { extractFingerprint } from "./fingerprint-extractor";
import type { ArgusPayload } from "../../helpers/payload-schema";

function basePayload(overrides: Partial<ArgusPayload> = {}): ArgusPayload {
  return {
    identifiers: { session_id: "sess-1" },
    hashes: { stable: "stable-abc", fuzzy: "0123456789abcdef" },
    device: {},
    ...overrides,
  };
}

describe("extractFingerprint", () => {
  describe("structural hashes", () => {
    it("should extract windowFeatures hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", windowFeatures: "wf-hash-123" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.window_features_hash).toBe("wf-hash-123");
    });

    it("should extract htmlElementVersion hash", () => {
      const payload = basePayload({
        hashes: {
          stable: "s",
          fuzzy: "f",
          htmlElementVersion: "html-hash-456",
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.html_element_hash).toBe("html-hash-456");
    });

    it("should extract css hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", css: "css-hash-789" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.css_hash).toBe("css-hash-789");
    });

    it("should extract svg hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", svg: "svg-hash-abc" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.svg_hash).toBe("svg-hash-abc");
    });

    it("should extract intl hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", intl: "intl-hash" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.intl_hash).toBe("intl-hash");
    });

    it("should extract features hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", features: "feat-hash" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.features_hash).toBe("feat-hash");
    });

    it("should extract consoleErrors hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", consoleErrors: "ce-hash" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.console_errors_hash).toBe("ce-hash");
    });

    it("should extract clientRects hash", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", clientRects: "cr-hash" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.client_rects_hash).toBe("cr-hash");
    });

    it("should extract all structural hashes together", () => {
      const payload = basePayload({
        hashes: {
          stable: "s",
          fuzzy: "f",
          maths: "maths-h",
          windowFeatures: "wf-h",
          htmlElementVersion: "html-h",
          css: "css-h",
          svg: "svg-h",
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.maths_hash).toBe("maths-h");
      expect(fp.window_features_hash).toBe("wf-h");
      expect(fp.html_element_hash).toBe("html-h");
      expect(fp.css_hash).toBe("css-h");
      expect(fp.svg_hash).toBe("svg-h");
    });
  });

  describe("webgl_extensions_count", () => {
    it("should extract extensions count from canvasWebgl", () => {
      const payload = basePayload({
        device: {
          canvasWebgl: {
            extensions: ["EXT_a", "EXT_b", "EXT_c"],
          },
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.webgl_extensions_count).toBe(3);
    });

    it("should not set count when extensions is not an array", () => {
      const payload = basePayload({
        device: { canvasWebgl: { extensions: "not-an-array" } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.webgl_extensions_count).toBeUndefined();
    });

    it("should not set count when canvasWebgl is missing", () => {
      const payload = basePayload({ device: {} });
      const fp = extractFingerprint(payload);
      expect(fp.webgl_extensions_count).toBeUndefined();
    });
  });

  describe("IP fallback from headers", () => {
    it("should use sigint IP when available", () => {
      const payload = basePayload({
        sigint: { tlsFingerprint: { ip: "10.0.0.1" } },
      });
      const fp = extractFingerprint(payload, {
        "X-Forwarded-For": "192.168.1.1",
      });
      expect(fp.ip_address).toBe("10.0.0.1");
    });

    it("should fall back to X-Forwarded-For when sigint IP is missing", () => {
      const payload = basePayload({
        sigint: { tlsFingerprint: { ip: null } },
      });
      const fp = extractFingerprint(payload, {
        "X-Forwarded-For": "192.168.1.1",
      });
      expect(fp.ip_address).toBe("192.168.1.1");
    });

    it("should fall back to X-Forwarded-For when sigint is undefined", () => {
      const payload = basePayload();
      const fp = extractFingerprint(payload, {
        "X-Forwarded-For": "203.0.113.5",
      });
      expect(fp.ip_address).toBe("203.0.113.5");
    });

    it("should use first IP from comma-separated X-Forwarded-For", () => {
      const payload = basePayload();
      const fp = extractFingerprint(payload, {
        "X-Forwarded-For": "203.0.113.5, 10.0.0.1, 172.16.0.1",
      });
      expect(fp.ip_address).toBe("203.0.113.5");
    });

    it("should not set IP when neither sigint nor headers provide it", () => {
      const payload = basePayload();
      const fp = extractFingerprint(payload);
      expect(fp.ip_address).toBeUndefined();
    });
  });

  describe("privacy mode detection", () => {
    it("should detect private browsing from incognito module", () => {
      const payload = basePayload({
        device: { incognito: { privateBrowsing: true } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.is_private_browsing).toBe(true);
    });

    it("should detect private browsing from isPrivate flag", () => {
      const payload = basePayload({
        device: { incognito: { isPrivate: true } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.is_private_browsing).toBe(true);
    });

    it("should not flag when incognito module shows non-private", () => {
      const payload = basePayload({
        device: { incognito: { privateBrowsing: false } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.is_private_browsing).toBeUndefined();
    });

    it("should detect privacy browser from resistance module", () => {
      const payload = basePayload({
        device: { resistance: { privacy: "brave" } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.privacy_browser).toBe("brave");
    });

    it("should ignore 'unknown' privacy value", () => {
      const payload = basePayload({
        device: { resistance: { privacy: "unknown" } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.privacy_browser).toBeUndefined();
    });
  });

  describe("existing extraction", () => {
    it("should extract stable and fuzzy hashes", () => {
      const payload = basePayload();
      const fp = extractFingerprint(payload);
      expect(fp.stable_hash).toBe("stable-abc");
      expect(fp.fuzzy_hash).toBe("0123456789abcdef");
    });

    it("should extract workerScope fields", () => {
      const payload = basePayload({
        device: {
          workerScope: {
            userAgent: "Mozilla/5.0",
            hardwareConcurrency: 8,
            deviceMemory: 16,
            webglRenderer: "ANGLE (NVIDIA)",
            timezoneLocation: "America/New_York",
          },
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.user_agent).toBe("Mozilla/5.0");
      expect(fp.hardware_concurrency).toBe(8);
      expect(fp.device_memory).toBe(16);
      expect(fp.gpu_renderer).toBe("ANGLE (NVIDIA)");
      expect(fp.timezone).toBe("America/New_York");
    });

    it("should extract screen dimensions", () => {
      const payload = basePayload({
        device: { screen: { width: 1920, height: 1080 } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.screen_dims).toBe("1920x1080");
    });

    it("should extract sigint fields", () => {
      const payload = basePayload({
        sigint: {
          tlsFingerprint: {
            ip: "1.2.3.4",
            ja3: "ja3-hash",
            ja4: "ja4-hash",
            id: "sigint-id-123",
          },
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.ip_address).toBe("1.2.3.4");
      expect(fp.ja3).toBe("ja3-hash");
      expect(fp.ja4).toBe("ja4-hash");
      expect(fp.sigint_id).toBe("sigint-id-123");
    });
  });
});
