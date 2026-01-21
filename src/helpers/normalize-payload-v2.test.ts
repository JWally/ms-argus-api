// src/helpers/normalize-payload-v2.test.ts
// AR-183: TDD tests for v1-to-v2 payload normalizer
import { describe, it, expect, afterEach } from "vitest";
import {
  normalizeToV2,
  isV1Payload,
  isV2Payload,
  getV1SunsetDate,
} from "./normalize-payload-v2";
import type { FingerprintPayload } from "../types";

// Sample v1 payload (current format)
const sampleV1Payload: FingerprintPayload = {
  session_id: "test-session-123",
  fingerprint: {
    stable_hash: "stable_abc123",
    fuzzy_hash: "fuzzy_def456",
    canvas_hash: "canvas_hash_789",
    webgl_hash: "webgl_hash_xyz",
    audio_hash: "audio_hash_abc",
    gpu_renderer: "ANGLE (Intel HD Graphics)",
    screen_dims: "1920x1080",
    timezone: "America/Chicago",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    evercookie_id: "ec_persistent_id",
    public_key: "-----BEGIN PUBLIC KEY-----\nMFkw...",
    hardware_concurrency: 8,
    device_memory: 16,
    is_headless: false,
    lie_count: 0,
  },
  sigint: {
    tlsFingerprint: {
      id: "sigint_cookie_id",
      ip: "192.168.1.100",
      ja3: "ja3_fingerprint",
      ja4: "ja4_fingerprint",
    },
    tcpProbe: {
      rttMs: 25,
      proxyScore: 0.1,
      vpnScore: 0.2,
    },
  },
  headers: {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "accept-language": "en-US,en;q=0.9",
  },
  timestamp: Date.now(),
};

// Sample v2 payload (new format)
const sampleV2Payload = {
  identifiers: {
    session_id: "test-session-456",
    evercookie_id: "ec_persistent_id",
    public_key: "-----BEGIN PUBLIC KEY-----\nMFkw...",
  },
  device: {
    hashes: {
      stable: "stable_abc123",
      fuzzy: "fuzzy_def456",
      canvas: "canvas_hash_789",
      webgl: "webgl_hash_xyz",
      audio: "audio_hash_abc",
    },
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    platform: "Win32",
    language: "en-US",
    languages: ["en-US", "en"],
    screen_width: 1920,
    screen_height: 1080,
    color_depth: 24,
    pixel_ratio: 1,
    gpu_vendor: "Intel Inc.",
    gpu_renderer: "ANGLE (Intel HD Graphics)",
    timezone_offset: -300,
    timezone_name: "America/Chicago",
    webdriver: false,
    headless_signals: [],
  },
};

describe("isV1Payload", () => {
  it("should return true for v1 payload structure", () => {
    expect(isV1Payload(sampleV1Payload)).toBe(true);
  });

  it("should return false for v2 payload structure", () => {
    expect(isV1Payload(sampleV2Payload)).toBe(false);
  });

  it("should return true for payload with session_id at root and fingerprint object", () => {
    const v1 = {
      session_id: "test",
      fingerprint: { stable_hash: "abc" },
      headers: {},
      timestamp: Date.now(),
    };
    expect(isV1Payload(v1)).toBe(true);
  });

  it("should return false for null/undefined", () => {
    expect(isV1Payload(null)).toBe(false);
    expect(isV1Payload(undefined)).toBe(false);
  });
});

describe("isV2Payload", () => {
  it("should return true for v2 payload structure", () => {
    expect(isV2Payload(sampleV2Payload)).toBe(true);
  });

  it("should return false for v1 payload structure", () => {
    expect(isV2Payload(sampleV1Payload)).toBe(false);
  });

  it("should return true for payload with identifiers.session_id and device.hashes", () => {
    const v2 = {
      identifiers: { session_id: "test" },
      device: {
        hashes: { stable: "a", fuzzy: "b" },
        user_agent: "test",
        platform: "test",
        language: "en",
        languages: ["en"],
        screen_width: 1920,
        screen_height: 1080,
        color_depth: 24,
        pixel_ratio: 1,
        timezone_offset: 0,
        timezone_name: "UTC",
        webdriver: false,
        headless_signals: [],
      },
    };
    expect(isV2Payload(v2)).toBe(true);
  });

  it("should return false for null/undefined", () => {
    expect(isV2Payload(null)).toBe(false);
    expect(isV2Payload(undefined)).toBe(false);
  });
});

describe("normalizeToV2", () => {
  it("should pass through v2 payloads unchanged", () => {
    const result = normalizeToV2(sampleV2Payload);
    expect(result.identifiers.session_id).toBe("test-session-456");
    expect(result.device.hashes.stable).toBe("stable_abc123");
  });

  it("should normalize v1 payload to v2 structure", () => {
    const result = normalizeToV2(sampleV1Payload);

    // Check identifiers
    expect(result.identifiers.session_id).toBe("test-session-123");
    expect(result.identifiers.evercookie_id).toBe("ec_persistent_id");
    expect(result.identifiers.public_key).toContain("BEGIN PUBLIC KEY");

    // Check device hashes
    expect(result.device.hashes.stable).toBe("stable_abc123");
    expect(result.device.hashes.fuzzy).toBe("fuzzy_def456");
    expect(result.device.hashes.canvas).toBe("canvas_hash_789");
    expect(result.device.hashes.webgl).toBe("webgl_hash_xyz");
    expect(result.device.hashes.audio).toBe("audio_hash_abc");

    // Check device properties
    expect(result.device.user_agent).toBe(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    );
    expect(result.device.gpu_renderer).toBe("ANGLE (Intel HD Graphics)");
    expect(result.device.screen_width).toBe(1920);
    expect(result.device.screen_height).toBe(1080);
    expect(result.device.timezone_name).toBe("America/Chicago");
    expect(result.device.webdriver).toBe(false);
    expect(result.device.headless_signals).toEqual([]);
  });

  it("should extract screen dimensions from screen_dims string", () => {
    const v1 = {
      session_id: "test",
      fingerprint: {
        stable_hash: "a",
        fuzzy_hash: "b",
        screen_dims: "2560x1440",
      },
      headers: {},
      timestamp: Date.now(),
    };
    const result = normalizeToV2(v1);
    expect(result.device.screen_width).toBe(2560);
    expect(result.device.screen_height).toBe(1440);
  });

  it("should include network data from sigint when present", () => {
    const result = normalizeToV2(sampleV1Payload);

    // Network should be populated from sigint
    expect(result.network).toBeDefined();
    expect(result.network?.ip).toBe("192.168.1.100");
    expect(result.network?.ja3).toBe("ja3_fingerprint");
    expect(result.network?.ja4).toBe("ja4_fingerprint");
    expect(result.network?.headers).toEqual(sampleV1Payload.headers);
  });

  it("should handle v1 payload without sigint data", () => {
    const v1WithoutSigint = {
      session_id: "test",
      fingerprint: {
        stable_hash: "abc",
        fuzzy_hash: "def",
        ip_address: "10.0.0.1",
      },
      headers: { "user-agent": "test" },
      timestamp: Date.now(),
    };
    const result = normalizeToV2(v1WithoutSigint);

    // Should use ip_address from fingerprint
    expect(result.network?.ip).toBe("10.0.0.1");
  });

  it("should handle minimal v1 payload", () => {
    const minimal = {
      session_id: "min-session",
      fingerprint: {
        stable_hash: "stable",
        fuzzy_hash: "fuzzy",
      },
      headers: {},
      timestamp: Date.now(),
    };
    const result = normalizeToV2(minimal);

    expect(result.identifiers.session_id).toBe("min-session");
    expect(result.device.hashes.stable).toBe("stable");
    expect(result.device.hashes.fuzzy).toBe("fuzzy");
    // Default values for required fields
    expect(result.device.user_agent).toBeDefined();
    expect(result.device.webdriver).toBe(false);
    expect(result.device.headless_signals).toEqual([]);
  });

  it("should map hardware_concurrency and device_memory correctly", () => {
    const result = normalizeToV2(sampleV1Payload);
    expect(result.device.hardware_concurrency).toBe(8);
    expect(result.device.device_memory).toBe(16);
  });

  it("should map bot detection signals to headless_signals", () => {
    const v1WithBot = {
      session_id: "bot-test",
      fingerprint: {
        stable_hash: "a",
        fuzzy_hash: "b",
        is_headless: true,
        lie_count: 5,
      },
      headers: {},
      timestamp: Date.now(),
    };
    const result = normalizeToV2(v1WithBot);
    expect(result.device.webdriver).toBe(true);
    // lie_count > 0 should add a signal
    expect(result.device.headless_signals).toContain("lies_detected");
  });
});

describe("V1_SUNSET_DATE configuration", () => {
  const originalEnv = process.env.V1_SUNSET_DATE;

  afterEach(() => {
    if (originalEnv) {
      process.env.V1_SUNSET_DATE = originalEnv;
    } else {
      delete process.env.V1_SUNSET_DATE;
    }
  });

  it("should return the sunset date from environment", () => {
    process.env.V1_SUNSET_DATE = "2025-06-01T00:00:00Z";
    const date = getV1SunsetDate();
    expect(date.getUTCFullYear()).toBe(2025);
    expect(date.getUTCMonth()).toBe(5); // June is 5 (0-indexed)
    expect(date.getUTCDate()).toBe(1);
  });

  it("should return a future default date if not configured", () => {
    delete process.env.V1_SUNSET_DATE;
    const date = getV1SunsetDate();
    // Default should be in the future
    expect(date.getTime()).toBeGreaterThan(Date.now());
  });
});
