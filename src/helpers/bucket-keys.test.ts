// src/helpers/bucket-keys.test.ts
// AR-117: Tests for shared bucket key utilities
// AR-134: Tenant removed from all bucket key functions
import { describe, it, expect } from "vitest";
import {
  buildBucketKeys,
  buildBucketKeysWithTypes,
  buildTier2BucketKeys,
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "./bucket-keys";
import { fnv1a } from "./hash";
import type { Fingerprint } from "../types/fingerprint";

describe("buildBucketKeys", () => {
  it("should return empty array when no compound signals available", () => {
    const fingerprint: Fingerprint = {};
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toEqual([]);
  });

  it("should build ip_ja4 bucket key", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.1",
      ja4: "t13d1516h2_8daaf6152771_02713d6af862",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toContain(
      "ip_ja4#192.168.1.1#t13d1516h2_8daaf6152771_02713d6af862",
    );
  });

  it("should build gpu_screen_tz bucket key", () => {
    const fingerprint: Fingerprint = {
      gpu_renderer: "ANGLE (Intel, Mesa Intel UHD Graphics 620)",
      screen_dims: "1920x1080",
      timezone: "America/New_York",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain("gpu_screen_tz");
    expect(keys[0]).toContain("1920x1080");
  });

  it("should build audio_canvas bucket key", () => {
    const fingerprint: Fingerprint = {
      audio_hash: "audio123",
      canvas_hash: "canvas456",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toContain("audio_canvas#audio123#canvas456");
  });

  it("should build all bucket keys when all signals present", () => {
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      ja4: "ja4hash",
      gpu_renderer: "GPU",
      screen_dims: "1080x720",
      timezone: "UTC",
      audio_hash: "audio",
      canvas_hash: "canvas",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(3);
  });

  // AR-80: Structural tier2 bucket tests
  it("should build maths_window bucket key", () => {
    const fingerprint: Fingerprint = {
      maths_hash: "maths123abc",
      window_features_hash: "winfeatures456def",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toContain("maths_window#maths123abc#winfeatures456def");
  });

  it("should build html_css bucket key", () => {
    const fingerprint: Fingerprint = {
      html_element_hash: "html789ghi",
      css_hash: "css012jkl",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toContain("html_css#html789ghi#css012jkl");
  });

  it("should build webgl_struct bucket key", () => {
    const fingerprint: Fingerprint = {
      webgl_hash: "webgl345mno",
      webgl_extensions_count: 65,
      svg_hash: "svg678pqr",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toContain("webgl_struct#webgl345mno#65#svg678pqr");
  });

  it("should build all 6 bucket types when all signals present", () => {
    const fingerprint: Fingerprint = {
      // Original 3 bucket signals
      ip_address: "10.0.0.1",
      ja4: "ja4hash",
      gpu_renderer: "GPU",
      screen_dims: "1080x720",
      timezone: "UTC",
      audio_hash: "audio",
      canvas_hash: "canvas",
      // AR-80: Structural signals
      maths_hash: "maths123",
      window_features_hash: "winfeatures456",
      html_element_hash: "html789",
      css_hash: "css012",
      webgl_hash: "webgl345",
      webgl_extensions_count: 65,
      svg_hash: "svg678",
    };

    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(6);
    expect(keys.filter((k) => k.includes("ip_ja4"))).toHaveLength(1);
    expect(keys.filter((k) => k.includes("gpu_screen_tz"))).toHaveLength(1);
    expect(keys.filter((k) => k.includes("audio_canvas"))).toHaveLength(1);
    expect(keys.filter((k) => k.includes("maths_window"))).toHaveLength(1);
    expect(keys.filter((k) => k.includes("html_css"))).toHaveLength(1);
    expect(keys.filter((k) => k.includes("webgl_struct"))).toHaveLength(1);
  });
});

describe("buildTier2BucketKeys (alias)", () => {
  it("should be identical to buildBucketKeys", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      ja4: "t13d1516h2_abc123",
      audio_hash: "audio123",
      canvas_hash: "canvas456",
    };

    const keys1 = buildBucketKeys(fingerprint);
    const keys2 = buildTier2BucketKeys(fingerprint);

    expect(keys1).toEqual(keys2);
  });

  it("should return empty array when no compound signals", () => {
    const fingerprint: Fingerprint = {};
    const keys = buildTier2BucketKeys(fingerprint);
    expect(keys).toEqual([]);
  });
});

describe("buildBucketKeysWithTypes", () => {
  it("should return correct evidence codes for each bucket type", () => {
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      ja4: "ja4hash",
      gpu_renderer: "GPU",
      screen_dims: "1080x720",
      timezone: "UTC",
      audio_hash: "audio",
      canvas_hash: "canvas",
      maths_hash: "maths123",
      window_features_hash: "winfeatures456",
      html_element_hash: "html789",
      css_hash: "css012",
      webgl_hash: "webgl345",
      webgl_extensions_count: 65,
      svg_hash: "svg678",
    };

    const results = buildBucketKeysWithTypes(fingerprint);
    expect(results).toHaveLength(6);

    const evidenceCodes = results.map((r) => r.evidenceCode);
    expect(evidenceCodes).toContain("IP_JA4_BUCKET");
    expect(evidenceCodes).toContain("GPU_SCREEN_TZ_BUCKET");
    expect(evidenceCodes).toContain("AUDIO_CANVAS_BUCKET");
    expect(evidenceCodes).toContain("MATHS_WINDOW_BUCKET");
    expect(evidenceCodes).toContain("HTML_CSS_BUCKET");
    expect(evidenceCodes).toContain("WEBGL_STRUCT_BUCKET");
  });

  it("should return IP_JA4_BUCKET evidence code for ip_ja4 bucket", () => {
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      ja4: "ja4hash",
    };

    const results = buildBucketKeysWithTypes(fingerprint);
    expect(results).toHaveLength(1);
    expect(results[0].evidenceCode).toBe("IP_JA4_BUCKET");
    expect(results[0].key).toContain("ip_ja4");
  });

  it("should return GPU_SCREEN_TZ_BUCKET evidence code", () => {
    const fingerprint: Fingerprint = {
      gpu_renderer: "GPU",
      screen_dims: "1080x720",
      timezone: "UTC",
    };

    const results = buildBucketKeysWithTypes(fingerprint);
    expect(results).toHaveLength(1);
    expect(results[0].evidenceCode).toBe("GPU_SCREEN_TZ_BUCKET");
  });

  it("should return AUDIO_CANVAS_BUCKET evidence code", () => {
    const fingerprint: Fingerprint = {
      audio_hash: "audio",
      canvas_hash: "canvas",
    };

    const results = buildBucketKeysWithTypes(fingerprint);
    expect(results).toHaveLength(1);
    expect(results[0].evidenceCode).toBe("AUDIO_CANVAS_BUCKET");
  });
});

describe("partial signals", () => {
  it("should not build ip_ja4 bucket when only ip_address present", () => {
    const fingerprint: Fingerprint = { ip_address: "10.0.0.1" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build ip_ja4 bucket when only ja4 present", () => {
    const fingerprint: Fingerprint = { ja4: "ja4hash" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build gpu_screen_tz bucket when only gpu_renderer present", () => {
    const fingerprint: Fingerprint = { gpu_renderer: "GPU" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build gpu_screen_tz bucket when missing timezone", () => {
    const fingerprint: Fingerprint = {
      gpu_renderer: "GPU",
      screen_dims: "1080x720",
    };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build audio_canvas bucket when only audio_hash present", () => {
    const fingerprint: Fingerprint = { audio_hash: "audio123" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build audio_canvas bucket when only canvas_hash present", () => {
    const fingerprint: Fingerprint = { canvas_hash: "canvas456" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build maths_window bucket when only maths_hash present", () => {
    const fingerprint: Fingerprint = { maths_hash: "maths123" };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should not build webgl_struct bucket when webgl_extensions_count is missing", () => {
    const fingerprint: Fingerprint = {
      webgl_hash: "webgl345",
      svg_hash: "svg678",
    };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(0);
  });

  it("should handle webgl_extensions_count of 0 correctly", () => {
    const fingerprint: Fingerprint = {
      webgl_hash: "webgl345",
      webgl_extensions_count: 0,
      svg_hash: "svg678",
    };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain("webgl_struct");
    expect(keys[0]).toContain("#0#");
  });
});

describe("buildSessionAnchorKey", () => {
  it("should return null when ip_address missing", () => {
    const fingerprint: Fingerprint = {
      user_agent: "Mozilla/5.0 Chrome/120",
      screen_dims: "1920x1080",
    };
    const key = buildSessionAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should return null when user_agent missing", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.1",
      screen_dims: "1920x1080",
    };
    const key = buildSessionAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should return null when screen_dims missing", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0 Chrome/120",
    };
    const key = buildSessionAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should return null when all required signals missing", () => {
    const fingerprint: Fingerprint = {};
    const key = buildSessionAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should build correct key format: session_anchor#ip#uaHash#screen", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
      screen_dims: "1920x1080",
    };
    const key = buildSessionAnchorKey(fingerprint);

    expect(key).not.toBeNull();
    expect(key).toContain("session_anchor#");
    expect(key).toContain("192.168.1.100");
    expect(key).toContain("1920x1080");
    // Should have 4 parts: type, ip, uaHash, screen
    expect(key!.split("#")).toHaveLength(4);
  });

  it("should hash user_agent with fnv1a, not include raw string", () => {
    const userAgent = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0";
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      user_agent: userAgent,
      screen_dims: "1080x720",
    };
    const key = buildSessionAnchorKey(fingerprint);

    expect(key).not.toBeNull();
    // Should NOT contain the raw user agent string
    expect(key).not.toContain(userAgent);
    // Should contain the fnv1a hash of user agent
    const expectedHash = fnv1a(userAgent);
    expect(key).toContain(expectedHash);
  });

  it("should produce consistent keys for same inputs", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 Chrome/120",
      screen_dims: "1920x1080",
    };

    const key1 = buildSessionAnchorKey(fingerprint);
    const key2 = buildSessionAnchorKey(fingerprint);

    expect(key1).toBe(key2);
  });

  it("should handle empty string signals as falsy", () => {
    const fingerprint: Fingerprint = {
      ip_address: "",
      user_agent: "Mozilla/5.0",
      screen_dims: "1920x1080",
    };
    const key = buildSessionAnchorKey(fingerprint);
    expect(key).toBeNull();
  });
});

describe("buildIpUaAnchorKey", () => {
  it("should return null when ip_address missing", () => {
    const fingerprint: Fingerprint = {
      user_agent: "Mozilla/5.0 Chrome/120",
    };
    const key = buildIpUaAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should return null when user_agent missing", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.1",
    };
    const key = buildIpUaAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should return null when both required signals missing", () => {
    const fingerprint: Fingerprint = {};
    const key = buildIpUaAnchorKey(fingerprint);
    expect(key).toBeNull();
  });

  it("should build correct key format: ip_ua_anchor#ip#uaHash", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
    };
    const key = buildIpUaAnchorKey(fingerprint);

    expect(key).not.toBeNull();
    expect(key).toContain("ip_ua_anchor#");
    expect(key).toContain("192.168.1.100");
    // Should have 3 parts: type, ip, uaHash
    expect(key!.split("#")).toHaveLength(3);
  });

  it("should NOT include screen_dims in key (by design)", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 Chrome/120",
      screen_dims: "1920x1080",
    };
    const key = buildIpUaAnchorKey(fingerprint);

    expect(key).not.toBeNull();
    // Should NOT contain screen dims
    expect(key).not.toContain("1920x1080");
    // Should only have 3 parts (no screen)
    expect(key!.split("#")).toHaveLength(3);
  });

  it("should hash user_agent with fnv1a, not include raw string", () => {
    const userAgent =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36";
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      user_agent: userAgent,
    };
    const key = buildIpUaAnchorKey(fingerprint);

    expect(key).not.toBeNull();
    // Should NOT contain the raw user agent string
    expect(key).not.toContain(userAgent);
    // Should contain the fnv1a hash of user agent
    const expectedHash = fnv1a(userAgent);
    expect(key).toContain(expectedHash);
  });

  it("should produce consistent keys for same inputs", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 Firefox/120",
    };

    const key1 = buildIpUaAnchorKey(fingerprint);
    const key2 = buildIpUaAnchorKey(fingerprint);

    expect(key1).toBe(key2);
  });

  it("should handle empty string signals as falsy", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "",
    };
    const key = buildIpUaAnchorKey(fingerprint);
    expect(key).toBeNull();
  });
});

describe("parity: session anchor vs ip_ua anchor", () => {
  it("should use same UA hash for both anchor types", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.100",
      user_agent: "Mozilla/5.0 Chrome/120",
      screen_dims: "1920x1080",
    };

    const sessionKey = buildSessionAnchorKey(fingerprint);
    const ipUaKey = buildIpUaAnchorKey(fingerprint);

    expect(sessionKey).not.toBeNull();
    expect(ipUaKey).not.toBeNull();

    // Extract UA hash from both keys
    const sessionParts = sessionKey!.split("#");
    const ipUaParts = ipUaKey!.split("#");

    // UA hash is at index 2 in both (after removing tenant)
    const sessionUaHash = sessionParts[2];
    const ipUaHash = ipUaParts[2];

    expect(sessionUaHash).toBe(ipUaHash);
  });

  it("session anchor includes screen_dims, ip_ua anchor does not", () => {
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      user_agent: "UA-String",
      screen_dims: "2560x1440",
    };

    const sessionKey = buildSessionAnchorKey(fingerprint);
    const ipUaKey = buildIpUaAnchorKey(fingerprint);

    expect(sessionKey).toContain("2560x1440");
    expect(ipUaKey).not.toContain("2560x1440");
  });
});

describe("edge cases", () => {
  it("should handle special characters in fingerprint values", () => {
    const fingerprint: Fingerprint = {
      ip_address: "192.168.1.1",
      ja4: "ja4#with#hashes",
    };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(1);
    // Key will contain the hash characters as-is
    expect(keys[0]).toBe("ip_ja4#192.168.1.1#ja4#with#hashes");
  });

  it("should handle unicode in GPU renderer", () => {
    const fingerprint: Fingerprint = {
      gpu_renderer: "NVIDIA GeForce \u2122 RTX",
      screen_dims: "1920x1080",
      timezone: "Europe/Paris",
    };
    const keys = buildBucketKeys(fingerprint);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toContain("\u2122");
  });

  it("should handle very long user agent strings", () => {
    const longUA = "Mozilla/5.0 ".repeat(100);
    const fingerprint: Fingerprint = {
      ip_address: "10.0.0.1",
      user_agent: longUA,
      screen_dims: "1920x1080",
    };

    const key = buildSessionAnchorKey(fingerprint);
    expect(key).not.toBeNull();
    // Key should be reasonably sized due to hashing
    expect(key!.length).toBeLessThan(200);
  });
});
