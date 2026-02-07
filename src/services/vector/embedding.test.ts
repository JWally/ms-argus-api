/**
 * @fileoverview Tests for fingerprint embedding service.
 */

import { describe, it, expect } from "vitest";
import {
  computeEmbedding,
  EMBEDDING_DIMENSIONS,
  EMBEDDING_VERSION,
  areEmbeddingsCompatible,
  assessEmbeddingQuality,
  type EmbeddingResult,
} from "./embedding";
import type { Fingerprint } from "../../types/fingerprint";

describe("computeEmbedding", () => {
  const baseFingerprint: Fingerprint = {
    stable_hash: "abc123def456",
    fuzzy_hash: "fedcba987654",
    html_element_hash: "1a2b3c4d",
    maths_hash: "5e6f7890",
    window_features_hash: "abcd1234",
    css_hash: "ef012345",
    svg_hash: "67890abc",
    intl_hash: "def12345",
    canvas_hash: "112233445566",
    webgl_hash: "aabbccddeeff",
    audio_hash: "11223344",
    client_rects_hash: "55667788",
    gpu_renderer: "NVIDIA GeForce GTX 1080",
    hardware_concurrency: 8,
    device_memory: 16,
    webgl_extensions_count: 35,
    screen_dims: "1920x1080",
    user_agent: "Mozilla/5.0 Chrome/120",
    ja3: "abc123",
    ja4: "def456",
    tcp_rtt_us: 25000,
    proxy_score: 0.1,
    vpn_score: 0.05,
    ip_address: "192.168.1.1",
    stun_public_ip: "8.8.8.8",
    stun_local_ip: "192.168.1.100",
    timezone: "America/New_York",
    is_private_browsing: false,
    privacy_browser: undefined,
    is_headless: false,
    lie_count: 0,
    features_hash: "aabbccdd",
    console_errors_hash: "1234",
  };

  it("produces correct dimensions", () => {
    const result = computeEmbedding(baseFingerprint);
    expect(result.vector.length).toBe(EMBEDDING_DIMENSIONS);
    expect(result.dimensions).toBe(EMBEDDING_DIMENSIONS);
    expect(result.dimensions).toBe(256);
  });

  it("includes version number", () => {
    const result = computeEmbedding(baseFingerprint);
    expect(result.version).toBe(EMBEDDING_VERSION);
    expect(result.version).toBe(5);
  });

  it("produces deterministic output for same input", () => {
    const result1 = computeEmbedding(baseFingerprint);
    const result2 = computeEmbedding(baseFingerprint);
    expect(result1.vector).toEqual(result2.vector);
  });

  it("handles missing fields gracefully", () => {
    const sparseFingerprint: Fingerprint = {
      stable_hash: "test123",
    };
    const result = computeEmbedding(sparseFingerprint);
    expect(result.vector.length).toBe(EMBEDDING_DIMENSIONS);
    expect(result.vector.every((v) => !isNaN(v))).toBe(true);
  });

  it("encodes hash values as bipolar (-1/+1)", () => {
    const result = computeEmbedding(baseFingerprint);
    // Structural section (first 48 dims) should be bipolar for hash values
    const structuralSection = result.vector.slice(0, 48);
    for (const val of structuralSection) {
      expect(val === -1 || val === 0 || val === 1).toBe(true);
    }
  });

  it("normalizes numeric values to 0-1 range", () => {
    const result = computeEmbedding(baseFingerprint);
    // v5: Hardware section starts at 96, first few values are normalized numerics
    const hwConcurrency = result.vector[96];
    const deviceMemory = result.vector[97];
    expect(hwConcurrency).toBeGreaterThanOrEqual(0);
    expect(hwConcurrency).toBeLessThanOrEqual(1);
    expect(deviceMemory).toBeGreaterThanOrEqual(0);
    expect(deviceMemory).toBeLessThanOrEqual(1);
  });

  it("pads remaining dimensions with zeros", () => {
    const result = computeEmbedding(baseFingerprint);
    // v5 reserved section (254-255) should be zeros
    // Structure: 48+48+14+46+22+76 = 254 used dims
    const reserved = result.vector.slice(254);
    expect(reserved.every((v) => v === 0)).toBe(true);
    expect(reserved.length).toBe(2);
  });

  it("prefers SimHash over SHA-256 in structural section", () => {
    const withSimHash: Fingerprint = {
      ...baseFingerprint,
      maths_simhash: "aaaa1111bbbb2222", // SimHash variant
      maths_hash: "5e6f7890", // SHA-256 hash
    };
    const withoutSimHash: Fingerprint = {
      ...baseFingerprint,
      maths_hash: "5e6f7890",
    };

    const resultWith = computeEmbedding(withSimHash);
    const resultWithout = computeEmbedding(withoutSimHash);

    // Structural section dims 8-15 are maths (second 8-dim block)
    const mathsWithSimHash = resultWith.vector.slice(8, 16);
    const mathsWithoutSimHash = resultWithout.vector.slice(8, 16);

    // SimHash should produce different encoding than SHA-256
    expect(mathsWithSimHash).not.toEqual(mathsWithoutSimHash);

    // When only SHA-256 is available, it should still produce valid bipolar
    for (const val of mathsWithoutSimHash) {
      expect(val === -1 || val === 1).toBe(true);
    }
  });

  it("falls back to SHA-256 when SimHash is absent", () => {
    const shaOnly: Fingerprint = {
      ...baseFingerprint,
      maths_simhash: undefined,
      maths_hash: "5e6f7890",
    };
    const result = computeEmbedding(shaOnly);

    // Maths is second structural block (dims 8-15)
    const mathsSection = result.vector.slice(8, 16);
    // Should be non-zero (from SHA-256 hash)
    expect(mathsSection.some((v) => v !== 0)).toBe(true);
  });

  it("encodes H2 fingerprint data", () => {
    const withH2: Fingerprint = {
      ...baseFingerprint,
      h2_settings_order: [
        "1:65536",
        "2:0",
        "3:100",
        "4:131072",
        "5:16384",
        "6:8192",
      ],
      h2_window_update: 12517377,
      h2_pseudo_header_order: "m,p,a,s",
      h2_header_order: ["user-agent", "accept", "accept-encoding"],
    };

    const resultWith = computeEmbedding(withH2);
    const resultWithout = computeEmbedding(baseFingerprint);

    // v5: Network starts at 110, H2 is after ja3(8)+ja4(8)+ip(8)+asn(3) = 27
    // H2 starts at dim 110+27 = 137, spans 14 dims (137-150)
    const h2With = resultWith.vector.slice(137, 151);
    const h2Without = resultWithout.vector.slice(137, 151);

    // H2 section should differ when H2 data is present
    expect(h2With).not.toEqual(h2Without);

    // H2 settings should be normalized values (0-1 range for settings)
    for (const val of h2With.slice(0, 6)) {
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(1);
    }
  });

  it("produces zeros for H2 when not present", () => {
    const result = computeEmbedding(baseFingerprint);
    // H2 starts at 137, spans 14 dims
    const h2Section = result.vector.slice(137, 151);
    expect(h2Section.every((v) => v === 0)).toBe(true);
  });

  it("does not include stable_hash in identity section", () => {
    const fp1: Fingerprint = {
      ...baseFingerprint,
      stable_hash: "aaaa1111",
      fuzzy_hash: "fedcba987654",
    };
    const fp2: Fingerprint = {
      ...baseFingerprint,
      stable_hash: "bbbb2222", // different stable_hash
      fuzzy_hash: "fedcba987654", // same fuzzy
    };

    const result1 = computeEmbedding(fp1);
    const result2 = computeEmbedding(fp2);

    // v5: Identity section starts at 178, spans 76 dims
    const identity1 = result1.vector.slice(178, 254);
    const identity2 = result2.vector.slice(178, 254);

    // With same fuzzy_hash, identity section should be identical
    // (stable_hash no longer encoded)
    expect(identity1).toEqual(identity2);
  });
});

describe("areEmbeddingsCompatible", () => {
  it("returns true for same version and dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 5,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 5,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(true);
  });

  it("returns false for different versions", () => {
    const a: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 4,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 5,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });

  it("returns false for different dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(128).fill(0),
      dimensions: 128,
      version: 5,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 5,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });
});

describe("EMBEDDING_DIMENSIONS", () => {
  it("is 256", () => {
    expect(EMBEDDING_DIMENSIONS).toBe(256);
  });
});

describe("assessEmbeddingQuality", () => {
  it("accepts full fingerprint with all signals", () => {
    const fullFingerprint: Fingerprint = {
      stable_hash: "abc123",
      fuzzy_hash: "def456",
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      css_hash: "hash4",
      svg_hash: "hash5",
      intl_hash: "hash6",
      canvas_hash: "canvas",
      webgl_hash: "webgl",
      audio_hash: "audio",
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0 Chrome/120",
    };

    const result = assessEmbeddingQuality(fullFingerprint);
    expect(result.acceptable).toBe(true);
    expect(result.score).toBeGreaterThan(0.5);
    expect(result.structuralCount).toBe(6);
    expect(result.renderingCount).toBe(3);
    expect(result.hardwareCount).toBe(4);
  });

  it("rejects skinny fingerprint missing structural hashes", () => {
    // Simulates the minimal V3 payloads from automation tests
    const skinnyFingerprint: Fingerprint = {
      stable_hash: "abc123",
      fuzzy_hash: "def456",
      canvas_hash: "canvas",
      webgl_hash: "webgl",
      audio_hash: "audio",
      // Missing: maths_hash, window_features_hash, html_element_hash, css_hash, svg_hash, intl_hash
      hardware_concurrency: 8,
      screen_dims: "1920x1080",
    };

    const result = assessEmbeddingQuality(skinnyFingerprint);
    expect(result.acceptable).toBe(false);
    expect(result.structuralCount).toBe(0);
    expect(result.reason).toContain("structural");
  });

  it("rejects fingerprint missing identity hashes", () => {
    const noIdentity: Fingerprint = {
      // Missing stable_hash and fuzzy_hash
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      css_hash: "hash4",
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0",
    };

    const result = assessEmbeddingQuality(noIdentity);
    expect(result.acceptable).toBe(false);
    expect(result.reason).toContain("identity");
  });

  it("accepts privacy browser with strong structural but no rendering", () => {
    // Brave browser blocks canvas/audio/webgl but we can still match on structural
    const braveFingerprint: Fingerprint = {
      stable_hash: "abc123",
      fuzzy_hash: "def456",
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      css_hash: "hash4",
      svg_hash: "hash5",
      intl_hash: "hash6",
      // No rendering hashes (blocked by Brave)
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0 Chrome/120",
      privacy_browser: "brave",
    };

    const result = assessEmbeddingQuality(braveFingerprint);
    // Should pass because structural count >= 4 compensates for missing rendering
    expect(result.acceptable).toBe(true);
    expect(result.structuralCount).toBe(6);
    expect(result.renderingCount).toBe(0);
  });

  it("rejects fingerprint with insufficient hardware signals", () => {
    const noHardware: Fingerprint = {
      stable_hash: "abc123",
      fuzzy_hash: "def456",
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      canvas_hash: "canvas",
      // Missing: hardware_concurrency, device_memory, screen_dims, user_agent
    };

    const result = assessEmbeddingQuality(noHardware);
    expect(result.acceptable).toBe(false);
    expect(result.hardwareCount).toBe(0);
    expect(result.reason).toContain("hardware");
  });

  it("calculates quality score as ratio of present signals", () => {
    const partialFingerprint: Fingerprint = {
      stable_hash: "abc123",
      fuzzy_hash: "def456",
      maths_hash: "hash1",
      window_features_hash: "hash2",
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      user_agent: "Mozilla/5.0",
    };

    const result = assessEmbeddingQuality(partialFingerprint);
    // 2 identity + 2 structural + 1 rendering + 2 hardware = 7 out of 15 max
    expect(result.score).toBeCloseTo(7 / 15, 2);
  });
});
