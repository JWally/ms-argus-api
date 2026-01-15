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

    // AR-83: Changed from toBe to toStrictEqual - we now copy flat fingerprints
    // to allow sigint data to override fields
    it("should detect flat format by stable_hash presence", () => {
      const flat = { stable_hash: "test123" };
      const result = normalizeFingerprint(flat);
      expect(result).toStrictEqual(flat); // Same content, but may be a copy for sigint override support
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

  // AR-83: Adversarial tests - testing robustness against malformed/unexpected input
  // These tests expose gaps in current implementation that need fixing
  describe("adversarial tests (AR-83)", () => {
    describe("type coercion", () => {
      it("should handle screen dimensions as strings", () => {
        const nested = {
          loose: {
            screen: {
              width: "1920" as unknown as number, // String instead of number
              height: "1080" as unknown as number,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should coerce strings to numbers and create valid screen_dims
        expect(result.screen_dims).toBe("1920x1080");
      });

      it("should handle hardwareConcurrency as string", () => {
        const nested = {
          loose: {
            navigator: {
              hardwareConcurrency: "8" as unknown as number, // String instead of number
              deviceMemory: "16" as unknown as number,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should coerce or handle string values
        expect(result.hardware_concurrency).toBe(8);
        expect(result.device_memory).toBe(16);
      });

      it("should handle boolean isHeadless as string 'true'", () => {
        const nested = {
          botSignals: {
            isHeadless: "true" as unknown as boolean, // String instead of boolean
            isPrivate: "false" as unknown as boolean,
          },
        };

        const result = normalizeFingerprint(nested);

        // Should coerce string 'true'/'false' to boolean
        expect(result.is_headless).toBe(true);
        expect(result.is_private_browsing).toBe(false);
      });

      it("should handle lieCount as string", () => {
        const nested = {
          botSignals: {
            lieCount: "5" as unknown as number,
          },
        };

        const result = normalizeFingerprint(nested);

        expect(result.lie_count).toBe(5);
      });

      it("should reject NaN values for numeric fields", () => {
        const nested = {
          loose: {
            screen: {
              width: NaN,
              height: 1080,
            },
            navigator: {
              hardwareConcurrency: NaN,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // NaN should not produce invalid screen_dims
        expect(result.screen_dims).toBeUndefined();
        expect(result.hardware_concurrency).toBeUndefined();
      });

      it("should handle Infinity values", () => {
        const nested = {
          loose: {
            navigator: {
              hardwareConcurrency: Infinity,
              deviceMemory: -Infinity,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Infinity should be rejected
        expect(result.hardware_concurrency).toBeUndefined();
        expect(result.device_memory).toBeUndefined();
      });
    });

    describe("empty values", () => {
      it("should treat empty string hash as undefined", () => {
        const nested = {
          loose: {
            canvas2d: { $hash: "" }, // Empty string
            maths: { $hash: "" },
          },
          hashes: {
            stable: "",
            fuzzy: "",
          },
        };

        const result = normalizeFingerprint(nested);

        // Empty strings should not be stored - they're not useful for matching
        expect(result.canvas_hash).toBeUndefined();
        expect(result.maths_hash).toBeUndefined();
        expect(result.stable_hash).toBeUndefined();
        expect(result.fuzzy_hash).toBeUndefined();
      });

      it("should handle whitespace-only strings as empty", () => {
        const nested = {
          loose: {
            canvas2d: { $hash: "   " },
            timezone: { location: "  ", zone: "\t\n" },
          },
        };

        const result = normalizeFingerprint(nested);

        expect(result.canvas_hash).toBeUndefined();
        expect(result.timezone).toBeUndefined();
      });

      it("should handle zero dimensions gracefully", () => {
        const nested = {
          loose: {
            screen: {
              width: 0,
              height: 0,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Zero dimensions are invalid - should not create screen_dims
        expect(result.screen_dims).toBeUndefined();
      });

      it("should handle negative screen dimensions", () => {
        const nested = {
          loose: {
            screen: {
              width: -1920,
              height: 1080,
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Negative dimensions are invalid
        expect(result.screen_dims).toBeUndefined();
      });
    });

    describe("unexpected structure", () => {
      it("should handle loose as array instead of object", () => {
        const nested = {
          loose: [{ canvas2d: { $hash: "test" } }], // Array instead of object
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        // Should not crash, just return empty or partial result
        expect(result.canvas_hash).toBeUndefined();
      });

      it("should handle hashes as string instead of object", () => {
        const nested = {
          hashes: "invalid_format", // String instead of object
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        expect(result.stable_hash).toBeUndefined();
      });

      it("should handle botSignals as array", () => {
        const nested = {
          botSignals: [{ isHeadless: true }], // Array instead of object
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        expect(result.is_headless).toBeUndefined();
      });

      it("should handle $hash as object instead of string", () => {
        const nested = {
          loose: {
            canvas2d: {
              $hash: { value: "hash_value" }, // Object instead of string
            },
          },
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        expect(result.canvas_hash).toBeUndefined();
      });

      it("should handle deeply nested unexpected structure", () => {
        const nested = {
          loose: {
            canvasWebgl: {
              gpu: {
                compressedGPU: {
                  renderer: "NVIDIA", // Object instead of string
                },
              },
            },
          },
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        // Should not use object as GPU renderer
        expect(result.gpu_renderer).toBeUndefined();
      });
    });

    describe("special characters and encoding", () => {
      it("should handle unicode in GPU renderer", () => {
        const nested = {
          loose: {
            canvasWebgl: {
              gpu: {
                compressedGPU: "NVIDIA® GeForce™ GTX 1080 🎮",
              },
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Unicode should be preserved
        expect(result.gpu_renderer).toBe("NVIDIA® GeForce™ GTX 1080 🎮");
      });

      it("should handle null bytes in strings", () => {
        const nested = {
          loose: {
            canvas2d: { $hash: "hash\x00with\x00nulls" },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should either sanitize or reject null bytes
        expect(result.canvas_hash).not.toContain("\x00");
      });

      it("should handle very long strings (potential DoS)", () => {
        const veryLongString = "a".repeat(100_000);
        const nested = {
          loose: {
            canvasWebgl: {
              gpu: {
                compressedGPU: veryLongString,
              },
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should truncate extremely long values to prevent storage issues
        expect(result.gpu_renderer?.length).toBeLessThan(10_000);
      });

      it("should handle script injection attempts in strings", () => {
        const nested = {
          loose: {
            timezone: {
              location: "<script>alert('xss')</script>America/Chicago",
            },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should sanitize or store as-is (storage is not HTML context)
        // The value should be stored without interpretation
        expect(result.timezone).toBeDefined();
      });
    });

    describe("prototype pollution resistance", () => {
      it("should not be affected by __proto__ in input", () => {
        const nested = JSON.parse(
          '{"__proto__": {"polluted": true}, "hashes": {"stable": "test"}}',
        );

        const result = normalizeFingerprint(nested);

        expect(result.stable_hash).toBe("test");
        // @ts-expect-error - checking prototype pollution
        expect(result.polluted).toBeUndefined();
        // @ts-expect-error - checking prototype pollution
        expect({}.polluted).toBeUndefined();
      });

      it("should not be affected by constructor pollution", () => {
        const nested = {
          constructor: { prototype: { polluted: true } },
          hashes: { stable: "safe" },
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        expect(result.stable_hash).toBe("safe");
      });
    });

    describe("null vs undefined handling", () => {
      it("should handle null values in nested objects", () => {
        const nested = {
          loose: {
            canvas2d: null,
            screen: null,
            timezone: null,
          },
          hashes: null,
          botSignals: null,
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        // Should not crash, return empty result
        expect(result.canvas_hash).toBeUndefined();
        expect(result.screen_dims).toBeUndefined();
        expect(result.stable_hash).toBeUndefined();
      });

      it("should handle explicit undefined values", () => {
        const nested = {
          loose: {
            canvas2d: { $hash: undefined },
            screen: { width: undefined, height: undefined },
          },
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        expect(result.canvas_hash).toBeUndefined();
        expect(result.screen_dims).toBeUndefined();
      });
    });

    describe("sigint adversarial", () => {
      it("should handle sigint.tcpProbe.rttMs as string", () => {
        const result = normalizeFingerprint(
          {},
          {
            tcpProbe: {
              rttMs: "25.5" as unknown as number,
            },
          },
        );

        // Should coerce string to number
        expect(result.tcp_rtt_us).toBe(25500);
      });

      it("should handle negative rttMs", () => {
        const result = normalizeFingerprint(
          {},
          {
            tcpProbe: {
              rttMs: -10,
            },
          },
        );

        // Negative RTT is invalid
        expect(result.tcp_rtt_us).toBeUndefined();
      });

      it("should handle proxyScore/vpnScore outside 0-1 range", () => {
        const result = normalizeFingerprint(
          {},
          {
            tcpProbe: {
              proxyScore: 1.5, // Invalid: > 1
              vpnScore: -0.5, // Invalid: < 0
            },
          },
        );

        // Scores should be clamped or rejected
        expect(result.proxy_score).toBeUndefined();
        expect(result.vpn_score).toBeUndefined();
      });

      it("should handle malformed IP addresses", () => {
        const result = normalizeFingerprint(
          {},
          {
            tlsFingerprint: {
              ip: "not-an-ip-address",
            },
          },
        );

        // Should validate IP format or store as-is
        expect(result.ip_address).toBeDefined();
      });
    });

    describe("mixed format edge cases", () => {
      it("should prefer sigint data even when fingerprint has same fields", () => {
        const fingerprint = {
          ip_address: "old-ip",
          ja4: "old-ja4",
          stable_hash: "should-not-be-processed", // Already flat
        };
        const sigint = {
          tlsFingerprint: {
            ip: "new-ip-from-sigint",
            ja4: "new-ja4-from-sigint",
          },
        };

        const result = normalizeFingerprint(fingerprint, sigint);

        // Since fingerprint has stable_hash, it's treated as flat and returned as-is
        // but sigint should still override fields
        expect(result.ip_address).toBe("new-ip-from-sigint");
        expect(result.ja4).toBe("new-ja4-from-sigint");
      });

      it("should handle fingerprint with both flat and nested data", () => {
        const mixed = {
          stable_hash: "flat-hash",
          loose: {
            canvas2d: { $hash: "nested-canvas" },
          },
        };

        const result = normalizeFingerprint(mixed);

        // Since stable_hash exists, it's treated as flat and returned as-is
        // The nested data is ignored
        expect(result.stable_hash).toBe("flat-hash");
        expect(result.canvas_hash).toBeUndefined(); // Nested ignored
      });
    });

    describe("large payload handling", () => {
      it("should handle payload with 1000+ fields in loose", () => {
        const loose: Record<string, { $hash: string }> = {};
        for (let i = 0; i < 1000; i++) {
          loose[`field_${i}`] = { $hash: `hash_${i}` };
        }

        const nested = {
          loose: {
            ...loose,
            canvas2d: { $hash: "important_canvas" },
          },
        };

        const result = normalizeFingerprint(nested);

        // Should still extract known fields
        expect(result.canvas_hash).toBe("important_canvas");
      });

      it("should handle deeply nested payload (100 levels)", () => {
        let deep: Record<string, unknown> = { $hash: "deep_hash" };
        for (let i = 0; i < 100; i++) {
          deep = { nested: deep };
        }

        const nested = {
          loose: {
            canvas2d: deep,
          },
        };

        const result = normalizeFingerprint(
          nested as unknown as Parameters<typeof normalizeFingerprint>[0],
        );

        // Should not find $hash at wrong level
        expect(result.canvas_hash).toBeUndefined();
      });
    });
  });
});
