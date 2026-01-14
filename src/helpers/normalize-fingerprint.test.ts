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
});
