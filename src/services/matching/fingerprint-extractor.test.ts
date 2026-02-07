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

  describe("expanded SimHash extraction", () => {
    it("should extract all SimHash variants from underscore-prefixed hash fields", () => {
      const payload = basePayload({
        hashes: {
          stable: "s",
          fuzzy: "f",
          _maths: "maths-sim",
          _windowFeatures: "wf-sim",
          _htmlElementVersion: "html-sim",
          _css: "css-sim",
          _svg: "svg-sim",
          _intl: "intl-sim",
          _features: "feat-sim",
          _clientRects: "cr-sim",
          _fonts: "fonts-sim",
          _canvas2d: "canvas-sim",
          _canvasWebgl: "webgl-sim",
          _offlineAudioContext: "audio-sim",
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.maths_simhash).toBe("maths-sim");
      expect(fp.window_features_simhash).toBe("wf-sim");
      expect(fp.html_element_simhash).toBe("html-sim");
      expect(fp.css_simhash).toBe("css-sim");
      expect(fp.svg_simhash).toBe("svg-sim");
      expect(fp.intl_simhash).toBe("intl-sim");
      expect(fp.features_simhash).toBe("feat-sim");
      expect(fp.client_rects_simhash).toBe("cr-sim");
      expect(fp.fonts_simhash).toBe("fonts-sim");
      expect(fp.canvas_simhash).toBe("canvas-sim");
      expect(fp.webgl_simhash).toBe("webgl-sim");
      expect(fp.audio_simhash).toBe("audio-sim");
    });

    it("should not set SimHash fields when underscore-prefixed hashes are absent", () => {
      const payload = basePayload({
        hashes: { stable: "s", fuzzy: "f", maths: "sha-hash" },
      });
      const fp = extractFingerprint(payload);
      expect(fp.maths_simhash).toBeUndefined();
      expect(fp.maths_hash).toBe("sha-hash");
    });
  });

  describe("H2 probe extraction", () => {
    it("should extract H2 fingerprint fields from sigint h2Probe", () => {
      const payload = basePayload({
        sigint: {
          h2Probe: {
            h2_fingerprint: {
              settings_order: ["1:65536", "2:0", "4:131072"],
              window_update: 12517377,
              pseudo_header_order: "m,p,a,s",
              header_order: ["user-agent", "accept", "accept-encoding"],
              fingerprint: "1:65536;2:0;4:131072|12517377|0|m,p,a,s",
              protocol: "h2",
            },
          },
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.h2_settings_order).toEqual(["1:65536", "2:0", "4:131072"]);
      expect(fp.h2_window_update).toBe(12517377);
      expect(fp.h2_pseudo_header_order).toBe("m,p,a,s");
      expect(fp.h2_header_order).toEqual([
        "user-agent",
        "accept",
        "accept-encoding",
      ]);
      expect(fp.h2_fingerprint_raw).toBe(
        "1:65536;2:0;4:131072|12517377|0|m,p,a,s",
      );
    });

    it("should handle missing h2Probe gracefully", () => {
      const payload = basePayload({
        sigint: { tlsFingerprint: { ip: "1.2.3.4" } },
      });
      const fp = extractFingerprint(payload);
      expect(fp.h2_settings_order).toBeUndefined();
      expect(fp.h2_window_update).toBeUndefined();
      expect(fp.h2_pseudo_header_order).toBeUndefined();
      expect(fp.h2_header_order).toBeUndefined();
      expect(fp.h2_fingerprint_raw).toBeUndefined();
    });

    it("should handle null h2_fingerprint gracefully", () => {
      const payload = basePayload({
        sigint: {
          h2Probe: { h2_fingerprint: null },
        },
      });
      const fp = extractFingerprint(payload);
      expect(fp.h2_settings_order).toBeUndefined();
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
