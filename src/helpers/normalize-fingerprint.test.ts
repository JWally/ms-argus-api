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

  describe("handles flat fingerprints", () => {
    it("should return flat fingerprint with primitive fields preserved", () => {
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
      expect(result.gpu_renderer).toBe("Intel HD Graphics");
      expect(result.screen_dims).toBe("1920x1080");
      expect(result.timezone).toBe("America/Chicago");
    });

    it("should preserve all primitive field types", () => {
      const flat = {
        stable_hash: "string_value",
        hardware_concurrency: 8,
        is_headless: false,
      };

      const result = normalizeFingerprint(flat);

      expect(result.stable_hash).toBe("string_value");
      expect(result.hardware_concurrency).toBe(8);
      expect(result.is_headless).toBe(false);
    });
  });

  describe("passthrough fields", () => {
    it("should pass through evercookie_id", () => {
      const input = { evercookie_id: "ec_123", stable_hash: "test" };
      const result = normalizeFingerprint(input);
      expect(result.evercookie_id).toBe("ec_123");
    });

    it("should pass through public_key", () => {
      const input = { public_key: "MFkw...", stable_hash: "test" };
      const result = normalizeFingerprint(input);
      expect(result.public_key).toBe("MFkw...");
    });

    it("should pass through sigint_id", () => {
      const input = { sigint_id: "sigint-uuid-456", stable_hash: "test" };
      const result = normalizeFingerprint(input);
      expect(result.sigint_id).toBe("sigint-uuid-456");
    });

    it("should pass through sigint fields", () => {
      const input = {
        stable_hash: "test",
        ip_address: "10.0.0.1",
        ja3: "ja3_hash",
        ja4: "ja4_hash",
        tcp_rtt_us: 12345,
      };
      const result = normalizeFingerprint(input);
      expect(result.ip_address).toBe("10.0.0.1");
      expect(result.ja3).toBe("ja3_hash");
      expect(result.ja4).toBe("ja4_hash");
      expect(result.tcp_rtt_us).toBe(12345);
    });
  });

  describe("extracts sigint data", () => {
    it("should extract sigint_id from sigint.aws_cf.id", () => {
      const result = normalizeFingerprint(
        {},
        { aws_cf: { id: "abc-123-def" } },
      );

      expect(result.sigint_id).toBe("abc-123-def");
    });

    it("should extract ja3 and ja4 from sigint.aws_cf", () => {
      const result = normalizeFingerprint(
        {},
        {
          aws_cf: {
            ja3: "ja3_hash_from_sigint",
            ja4: "ja4_hash_from_sigint",
          },
        },
      );

      expect(result.ja3).toBe("ja3_hash_from_sigint");
      expect(result.ja4).toBe("ja4_hash_from_sigint");
    });

    it("should extract ip_address from sigint.aws_cf.ip", () => {
      const result = normalizeFingerprint(
        {},
        { aws_cf: { ip: "192.168.1.100" } },
      );

      expect(result.ip_address).toBe("192.168.1.100");
    });

    it("should extract tcp probe data", () => {
      const result = normalizeFingerprint(
        {},
        {
          tcp_probe: {
            rttMs: 15.5,
          },
        },
      );

      expect(result.tcp_rtt_us).toBe(15500); // ms to μs
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
        stable_hash: "test",
        ja4: "old_ja4_from_fingerprint",
        ip_address: "old_ip",
      };
      const sigint = {
        aws_cf: {
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
        aws_cf: {
          id: "sigint-uuid-456",
          new: false,
          ip: "203.0.113.50",
          asn: "AS12345",
          country: "US",
          ja3: "full_ja3_hash",
          ja4: "full_ja4_hash",
        },
        tcp_probe: {
          rttMs: 25,
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
      expect(result.evercookie_id).toBe("favicon-persistent-id");
    });

    it("should handle null sigint gracefully", () => {
      const result = normalizeFingerprint({ stable_hash: "test" }, null);
      expect(result.stable_hash).toBe("test");
    });

    it("should handle undefined sigint gracefully", () => {
      const result = normalizeFingerprint({ stable_hash: "test" });
      expect(result.stable_hash).toBe("test");
    });

    it("should handle sigint with null aws_cf", () => {
      const result = normalizeFingerprint({}, { aws_cf: null });
      expect(result.sigint_id).toBeUndefined();
    });
  });

  describe("sigint adversarial", () => {
    it("should handle sigint.tcp_probe.rttMs as string", () => {
      const result = normalizeFingerprint(
        {},
        {
          tcp_probe: {
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
          tcp_probe: {
            rttMs: -10,
          },
        },
      );

      // Negative RTT is invalid
      expect(result.tcp_rtt_us).toBeUndefined();
    });

    it("should handle malformed IP addresses", () => {
      const result = normalizeFingerprint(
        {},
        {
          aws_cf: {
            ip: "not-an-ip-address",
          },
        },
      );

      // Should store as-is (validation is separate concern)
      expect(result.ip_address).toBe("not-an-ip-address");
    });
  });

  describe("strips nested objects from hybrid payloads", () => {
    it("should strip nested objects when flat hashes are present", () => {
      // Real client payloads can have BOTH flat fields AND nested objects
      // The nested objects can contain numbers > MAX_SAFE_INTEGER
      // which cause DynamoDB marshalling errors
      const hybridPayload = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
        public_key: "MFkwTest==",
        hardware_concurrency: 8,
        is_headless: false,
        someNestedObject: {
          data: {
            bigNumber: 9.199870313877772e307, // > MAX_SAFE_INTEGER
          },
        },
      };

      const result = normalizeFingerprint(hybridPayload);

      expect(result.stable_hash).toBe("stable123");
      expect(result.fuzzy_hash).toBe("fuzzy456");
      expect(result.public_key).toBe("MFkwTest==");
      expect(result.hardware_concurrency).toBe(8);
      expect(result.is_headless).toBe(false);

      expect(
        (result as Record<string, unknown>).someNestedObject,
      ).toBeUndefined();
    });

    it("should strip arrays from hybrid payloads", () => {
      const hybridPayload = {
        stable_hash: "stable123",
        someArray: [1, 2, 3],
        anotherArray: ["a", "b", "c"],
      };

      const result = normalizeFingerprint(hybridPayload);

      expect(result.stable_hash).toBe("stable123");
      expect((result as Record<string, unknown>).someArray).toBeUndefined();
      expect((result as Record<string, unknown>).anotherArray).toBeUndefined();
    });

    it("should preserve null and undefined values", () => {
      const payload = {
        stable_hash: "stable123",
        some_null_field: null,
        some_undefined_field: undefined,
      };

      const result = normalizeFingerprint(payload);

      expect(result.stable_hash).toBe("stable123");
      expect((result as Record<string, unknown>).some_null_field).toBeNull();
      expect(
        (result as Record<string, unknown>).some_undefined_field,
      ).toBeUndefined();
    });
  });

  describe("special characters and encoding", () => {
    it("should handle unicode in strings", () => {
      const payload = {
        stable_hash: "test",
        gpu_renderer: "NVIDIA® GeForce™ GTX 1080 🎮",
      };

      const result = normalizeFingerprint(payload);

      // Unicode should be preserved
      expect(result.gpu_renderer).toBe("NVIDIA® GeForce™ GTX 1080 🎮");
    });
  });
});
