// src/helpers/normalize-fingerprint.test.ts
// AR-73: Tests for fingerprint normalization
// AR-77: Updated to use correct web library field names (canvas2d, offlineAudioContext, canvasWebgl)

import { describe, it, expect } from "vitest";
import { normalizeFingerprint } from "./normalize-fingerprint";

describe("normalizeFingerprint", () => {
  describe("handles undefined/empty input", () => {
    it("should return empty object for undefined", () => {
      expect(normalizeFingerprint(undefined)).toEqual({});
    });

    it("should return empty object for empty object", () => {
      expect(normalizeFingerprint({})).toEqual({});
    });
  });

  describe("passes through already-flat fingerprints", () => {
    it("should return flat fingerprint unchanged", () => {
      const flat = {
        stable_hash: "abc123",
        fuzzy_hash: "def456",
        canvas_hash: "canvas123",
        gpu_renderer: "Intel HD Graphics",
        screen_dims: "1920x1080",
        timezone: "America/Chicago",
      };

      const result = normalizeFingerprint(flat);

      expect(result.stable_hash).toBe("abc123");
      expect(result.fuzzy_hash).toBe("def456");
      expect(result.canvas_hash).toBe("canvas123");
    });

    it("should detect flat format by stable_hash presence", () => {
      const flat = { stable_hash: "test123" };
      const result = normalizeFingerprint(flat);
      expect(result).toBe(flat); // Same reference - no transformation needed
    });
  });

  describe("transforms nested web library format", () => {
    it("should extract hashes from nested structure", () => {
      const nested = {
        hashes: {
          stable: "stable_hash_value",
          fuzzy: "fuzzy_hash_value",
          loose: "loose_hash_value",
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.stable_hash).toBe("stable_hash_value");
      expect(result.fuzzy_hash).toBe("fuzzy_hash_value");
    });

    // AR-77: Field is canvas2d (not canvas)
    it("should extract canvas hash from loose.canvas2d.$hash", () => {
      const nested = {
        loose: {
          canvas2d: {
            $hash: "canvas_hash_123",
            dataURI: "data:image/png;base64,...",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.canvas_hash).toBe("canvas_hash_123");
    });

    // AR-77: Field is offlineAudioContext (not audio)
    it("should extract audio hash from loose.offlineAudioContext.$hash", () => {
      const nested = {
        loose: {
          offlineAudioContext: {
            $hash: "audio_hash_456",
            totalUniqueSamples: 123,
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.audio_hash).toBe("audio_hash_456");
    });

    // AR-77: Field is canvasWebgl.gpu.compressedGPU (not webgl.gpu)
    it("should extract GPU renderer from loose.canvasWebgl.gpu.compressedGPU", () => {
      const nested = {
        loose: {
          canvasWebgl: {
            gpu: {
              compressedGPU: "ANGLE (Intel, Intel HD Graphics 630)",
            },
            $hash: "webgl_hash",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.gpu_renderer).toBe("ANGLE (Intel, Intel HD Graphics 630)");
      expect(result.webgl_hash).toBe("webgl_hash");
    });

    // AR-77: Fallback to canvasWebgl.parameters.renderer
    it("should extract GPU renderer from loose.canvasWebgl.parameters.renderer", () => {
      const nested = {
        loose: {
          canvasWebgl: {
            parameters: {
              renderer: "Intel HD Graphics 4000",
            },
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.gpu_renderer).toBe("Intel HD Graphics 4000");
    });

    it("should construct screen_dims from loose.screen", () => {
      const nested = {
        loose: {
          screen: {
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1040,
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.screen_dims).toBe("1920x1080");
    });

    it("should extract timezone from loose.timezone.location", () => {
      const nested = {
        loose: {
          timezone: {
            location: "America/New_York",
            zone: "EST",
            offset: -5,
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.timezone).toBe("America/New_York");
    });

    it("should fall back to timezone.zone if location not present", () => {
      const nested = {
        loose: {
          timezone: {
            zone: "PST",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.timezone).toBe("PST");
    });

    it("should extract navigator signals", () => {
      const nested = {
        loose: {
          navigator: {
            hardwareConcurrency: 8,
            deviceMemory: 16,
            platform: "Linux x86_64",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.hardware_concurrency).toBe(8);
      expect(result.device_memory).toBe(16);
    });

    it("should extract bot signals", () => {
      const nested = {
        botSignals: {
          isHeadless: true,
          lieCount: 5,
          botHash: "bot_hash_789",
          isPrivate: true,
          hasLies: true,
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.is_headless).toBe(true);
      expect(result.lie_count).toBe(5);
      expect(result.bot_hash).toBe("bot_hash_789");
      expect(result.is_private_browsing).toBe(true);
    });
  });

  // AR-77: Updated to use correct web library field names
  describe("handles complete web library payload", () => {
    it("should transform full nested structure to flat format", () => {
      const fullNested = {
        loose: {
          canvas2d: { $hash: "canvas_abc" },
          offlineAudioContext: { $hash: "audio_def" },
          canvasWebgl: {
            gpu: { compressedGPU: "NVIDIA GeForce GTX 1080" },
            $hash: "webgl_ghi",
          },
          screen: { width: 2560, height: 1440 },
          timezone: { location: "Europe/London" },
          navigator: { hardwareConcurrency: 12, deviceMemory: 32 },
        },
        hashes: {
          stable: "stable_main",
          fuzzy: "fuzzy_main",
        },
        botSignals: {
          isHeadless: false,
          lieCount: 0,
          isPrivate: false,
        },
        meta: {
          timestamp: 1234567890,
          version: "1.0.0",
        },
        // Passthrough fields from sigint
        ip_address: "192.168.1.1",
        ja4: "t13d1715h2_abc_def",
      };

      const result = normalizeFingerprint(fullNested);

      // Hashes
      expect(result.stable_hash).toBe("stable_main");
      expect(result.fuzzy_hash).toBe("fuzzy_main");

      // Canvas/Audio/WebGL
      expect(result.canvas_hash).toBe("canvas_abc");
      expect(result.audio_hash).toBe("audio_def");
      expect(result.gpu_renderer).toBe("NVIDIA GeForce GTX 1080");
      expect(result.webgl_hash).toBe("webgl_ghi");

      // Screen/Timezone
      expect(result.screen_dims).toBe("2560x1440");
      expect(result.timezone).toBe("Europe/London");

      // Navigator
      expect(result.hardware_concurrency).toBe(12);
      expect(result.device_memory).toBe(32);

      // Bot signals
      expect(result.is_headless).toBe(false);
      expect(result.lie_count).toBe(0);
      expect(result.is_private_browsing).toBe(false);

      // Passthrough fields
      expect(result.ip_address).toBe("192.168.1.1");
      expect(result.ja4).toBe("t13d1715h2_abc_def");
    });
  });

  describe("passthrough fields", () => {
    it("should pass through evercookie_id", () => {
      const input = { evercookie_id: "ec_123" };
      const result = normalizeFingerprint(input);
      expect(result.evercookie_id).toBe("ec_123");
    });

    it("should pass through public_key", () => {
      const input = { public_key: "MFkw..." };
      const result = normalizeFingerprint(input);
      expect(result.public_key).toBe("MFkw...");
    });

    // AR-81: Third-party cookie from sigint service
    it("should pass through sigint_id", () => {
      const input = { sigint_id: "sigint-uuid-456" };
      const result = normalizeFingerprint(input);
      expect(result.sigint_id).toBe("sigint-uuid-456");
    });

    it("should pass through sigint fields", () => {
      const input = {
        ip_address: "10.0.0.1",
        ja3: "ja3_hash",
        ja4: "ja4_hash",
        tcp_rtt_us: 12345,
        proxy_score: 0.5,
        vpn_score: 0.3,
      };
      const result = normalizeFingerprint(input);
      expect(result.ip_address).toBe("10.0.0.1");
      expect(result.ja3).toBe("ja3_hash");
      expect(result.ja4).toBe("ja4_hash");
      expect(result.tcp_rtt_us).toBe(12345);
      expect(result.proxy_score).toBe(0.5);
      expect(result.vpn_score).toBe(0.3);
    });
  });

  // AR-80: Structural fingerprint signals
  describe("extracts structural signals (AR-80)", () => {
    it("should extract maths_hash from loose.maths.$hash", () => {
      const nested = {
        loose: {
          maths: {
            $hash: "maths_hash_123",
            data: { "Math.acos(0.123)": 1.4470808451078687 },
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.maths_hash).toBe("maths_hash_123");
    });

    it("should extract window_features_hash from loose.windowFeatures.$hash", () => {
      const nested = {
        loose: {
          windowFeatures: {
            $hash: "window_features_hash_456",
            keys: ["devicePixelRatio", "innerWidth"],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.window_features_hash).toBe("window_features_hash_456");
    });

    it("should extract html_element_hash from loose.htmlElementVersion.$hash", () => {
      const nested = {
        loose: {
          htmlElementVersion: {
            $hash: "html_element_hash_789",
            version: "HTML5",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.html_element_hash).toBe("html_element_hash_789");
    });

    it("should extract css_hash from loose.css.$hash", () => {
      const nested = {
        loose: {
          css: {
            $hash: "css_hash_abc",
            keys: ["grid", "flexbox"],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.css_hash).toBe("css_hash_abc");
    });

    it("should extract features_hash from loose.features.$hash", () => {
      const nested = {
        loose: {
          features: {
            $hash: "features_hash_def",
            detected: { webgl2: true },
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.features_hash).toBe("features_hash_def");
    });

    it("should extract svg_hash from loose.svg.$hash", () => {
      const nested = {
        loose: {
          svg: {
            $hash: "svg_hash_ghi",
            supported: ["path", "rect"],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.svg_hash).toBe("svg_hash_ghi");
    });

    it("should extract client_rects_hash from loose.clientRects.$hash", () => {
      const nested = {
        loose: {
          clientRects: {
            $hash: "client_rects_hash_jkl",
            data: { width: 100.5, height: 20.25 },
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.client_rects_hash).toBe("client_rects_hash_jkl");
    });

    it("should extract intl_hash from loose.intl.$hash", () => {
      const nested = {
        loose: {
          intl: {
            $hash: "intl_hash_mno",
            locale: "en-US",
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.intl_hash).toBe("intl_hash_mno");
    });

    it("should extract console_errors_hash from loose.consoleErrors.$hash", () => {
      const nested = {
        loose: {
          consoleErrors: {
            $hash: "console_errors_hash_pqr",
            errors: [],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.console_errors_hash).toBe("console_errors_hash_pqr");
    });

    it("should extract webgl_extensions_count from loose.canvasWebgl.extensions.length", () => {
      const nested = {
        loose: {
          canvasWebgl: {
            $hash: "webgl_hash",
            extensions: [
              "WEBGL_debug_renderer_info",
              "EXT_texture_filter_anisotropic",
              "OES_texture_float",
            ],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.webgl_extensions_count).toBe(3);
    });

    it("should extract all structural signals from complete payload", () => {
      const nested = {
        loose: {
          maths: { $hash: "maths_abc" },
          windowFeatures: { $hash: "window_def" },
          htmlElementVersion: { $hash: "html_ghi" },
          css: { $hash: "css_jkl" },
          features: { $hash: "features_mno" },
          svg: { $hash: "svg_pqr" },
          clientRects: { $hash: "rects_stu" },
          intl: { $hash: "intl_vwx" },
          consoleErrors: { $hash: "errors_yza" },
          canvasWebgl: {
            $hash: "webgl_bcd",
            extensions: ["ext1", "ext2", "ext3", "ext4", "ext5"],
          },
        },
      };

      const result = normalizeFingerprint(nested);

      expect(result.maths_hash).toBe("maths_abc");
      expect(result.window_features_hash).toBe("window_def");
      expect(result.html_element_hash).toBe("html_ghi");
      expect(result.css_hash).toBe("css_jkl");
      expect(result.features_hash).toBe("features_mno");
      expect(result.svg_hash).toBe("svg_pqr");
      expect(result.client_rects_hash).toBe("rects_stu");
      expect(result.intl_hash).toBe("intl_vwx");
      expect(result.console_errors_hash).toBe("errors_yza");
      expect(result.webgl_hash).toBe("webgl_bcd");
      expect(result.webgl_extensions_count).toBe(5);
    });
  });

  describe("edge cases", () => {
    it("should handle missing nested objects gracefully", () => {
      const partial = {
        hashes: { stable: "only_stable" },
        // No loose, botSignals, etc.
      };

      const result = normalizeFingerprint(partial);

      expect(result.stable_hash).toBe("only_stable");
      expect(result.canvas_hash).toBeUndefined();
      expect(result.gpu_renderer).toBeUndefined();
    });

    // AR-77: Updated to use correct field name canvas2d
    it("should handle partial loose data", () => {
      const partial = {
        loose: {
          canvas2d: { $hash: "canvas_only" },
          // No offlineAudioContext, canvasWebgl, screen, etc.
        },
      };

      const result = normalizeFingerprint(partial);

      expect(result.canvas_hash).toBe("canvas_only");
      expect(result.audio_hash).toBeUndefined();
      expect(result.screen_dims).toBeUndefined();
    });

    it("should not create screen_dims if only width is present", () => {
      const partial = {
        loose: {
          screen: { width: 1920 },
        },
      };

      const result = normalizeFingerprint(partial);

      expect(result.screen_dims).toBeUndefined();
    });
  });

  // AR-81: Sigint data extraction tests
  describe("extracts sigint data (AR-81)", () => {
    it("should extract sigint_id from sigint.tlsFingerprint.id", () => {
      const result = normalizeFingerprint(
        {},
        { tlsFingerprint: { id: "abc-123-def" } },
      );

      expect(result.sigint_id).toBe("abc-123-def");
    });

    it("should extract ja3 and ja4 from sigint.tlsFingerprint", () => {
      const result = normalizeFingerprint(
        {},
        {
          tlsFingerprint: {
            ja3: "ja3_hash_from_sigint",
            ja4: "ja4_hash_from_sigint",
          },
        },
      );

      expect(result.ja3).toBe("ja3_hash_from_sigint");
      expect(result.ja4).toBe("ja4_hash_from_sigint");
    });

    it("should extract ip_address from sigint.tlsFingerprint.ip", () => {
      const result = normalizeFingerprint(
        {},
        { tlsFingerprint: { ip: "192.168.1.100" } },
      );

      expect(result.ip_address).toBe("192.168.1.100");
    });

    it("should extract tcp probe data", () => {
      const result = normalizeFingerprint(
        {},
        {
          tcpProbe: {
            rttMs: 15.5,
            proxyScore: 0.2,
            vpnScore: 0.1,
          },
        },
      );

      expect(result.tcp_rtt_us).toBe(15500); // ms to μs
      expect(result.proxy_score).toBe(0.2);
      expect(result.vpn_score).toBe(0.1);
    });

    it("should extract evercookie_id from faviconCache.deviceId", () => {
      const result = normalizeFingerprint(
        {},
        { faviconCache: { deviceId: "favicon-device-123" } },
      );

      expect(result.evercookie_id).toBe("favicon-device-123");
    });

    it("should override fingerprint fields with sigint data", () => {
      const fingerprint = {
        ja4: "old_ja4_from_fingerprint",
        ip_address: "old_ip",
      };
      const sigint = {
        tlsFingerprint: {
          ja4: "new_ja4_from_sigint",
          ip: "new_ip_from_edge",
        },
      };

      const result = normalizeFingerprint(fingerprint, sigint);

      // sigint data should take precedence
      expect(result.ja4).toBe("new_ja4_from_sigint");
      expect(result.ip_address).toBe("new_ip_from_edge");
    });

    it("should handle complete sigint payload", () => {
      const sigint = {
        tlsFingerprint: {
          id: "sigint-uuid-456",
          new: false,
          ip: "203.0.113.50",
          asn: "AS12345",
          country: "US",
          ja3: "full_ja3_hash",
          ja4: "full_ja4_hash",
        },
        tcpProbe: {
          rttMs: 25,
          proxyScore: 0.05,
          vpnScore: 0.0,
        },
        faviconCache: {
          deviceId: "favicon-persistent-id",
        },
      };

      const result = normalizeFingerprint({}, sigint);

      expect(result.sigint_id).toBe("sigint-uuid-456");
      expect(result.ip_address).toBe("203.0.113.50");
      expect(result.ja3).toBe("full_ja3_hash");
      expect(result.ja4).toBe("full_ja4_hash");
      expect(result.tcp_rtt_us).toBe(25000);
      expect(result.proxy_score).toBe(0.05);
      expect(result.vpn_score).toBe(0.0);
      expect(result.evercookie_id).toBe("favicon-persistent-id");
    });

    it("should handle null sigint gracefully", () => {
      const result = normalizeFingerprint({}, null);
      expect(result).toEqual({});
    });

    it("should handle undefined sigint gracefully", () => {
      const result = normalizeFingerprint({}, undefined);
      expect(result).toEqual({});
    });

    it("should handle sigint with null tlsFingerprint", () => {
      const result = normalizeFingerprint({}, { tlsFingerprint: null });
      expect(result.sigint_id).toBeUndefined();
    });
  });
});
