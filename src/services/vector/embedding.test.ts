/**
 * @fileoverview Tests for fingerprint embedding service.
 */

import { describe, it, expect } from "vitest";
import {
  computeEmbedding,
  computeWeightedEmbedding,
  EMBEDDING_DIMENSIONS,
  EMBEDDING_VERSION,
  WEIGHTED_EMBEDDING_VERSION,
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
    expect(result.dimensions).toBe(512);
  });

  it("includes version number", () => {
    const result = computeEmbedding(baseFingerprint);
    expect(result.version).toBe(EMBEDDING_VERSION);
    expect(result.version).toBe(12);
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
    // v12: Structural section (first 191 dims) should be bipolar for hash values
    const structuralSection = result.vector.slice(0, 191);
    for (const val of structuralSection) {
      expect(val === -1 || val === 0 || val === 1).toBe(true);
    }
  });

  it("normalizes behavioral numeric values to 0-1 range", () => {
    const result = computeEmbedding(baseFingerprint);
    // v12: Behavioral section starts at 316
    // timezone (24 dims via stringToVector) = 316-339, each in 0-1
    // tz_offset (1 dim normalized) = 340
    const tzOffset = result.vector[340];
    expect(tzOffset).toBeGreaterThanOrEqual(0);
    expect(tzOffset).toBeLessThanOrEqual(1);
  });

  it("uses all 512 dimensions with six sections", () => {
    const result = computeEmbedding(baseFingerprint);
    // v12: 191+76+44+5+64+132 = 512 used dims
    expect(result.vector.length).toBe(512);
    // Rendering section [191-266] should have non-zero values from canvas/webgl hashes
    const renderingSection = result.vector.slice(191, 267);
    expect(renderingSection.some((v) => v !== 0)).toBe(true);
    // Hardware section [267-310] should have non-zero values
    const hardwareSection = result.vector.slice(267, 311);
    expect(hardwareSection.some((v) => v !== 0)).toBe(true);
    // Network section [311-315] should be all zeros (ablation)
    const networkSection = result.vector.slice(311, 316);
    expect(networkSection.every((v) => v === 0)).toBe(true);
    // Behavioral section [316-379] should have non-zero values from timezone/features
    const behavioralSection = result.vector.slice(316, 380);
    expect(behavioralSection.some((v) => v !== 0)).toBe(true);
    // Identity section [380-511] should have non-zero values from fuzzy_hash
    const identitySection = result.vector.slice(380, 512);
    expect(identitySection.some((v) => v !== 0)).toBe(true);
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

    // v12: Maths is at dims 159-166 (after cssMedia(68)+css(34)+screen(33)+htmlElement(24) = 159)
    const mathsWithSimHash = resultWith.vector.slice(159, 167);
    const mathsWithoutSimHash = resultWithout.vector.slice(159, 167);

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

    // v12: Maths is at dims 159-166
    const mathsSection = result.vector.slice(159, 167);
    // Should be non-zero (from SHA-256 hash)
    expect(mathsSection.some((v) => v !== 0)).toBe(true);
  });

  it("includes hardware and identity but zeroes network", () => {
    const fp1: Fingerprint = {
      ...baseFingerprint,
      hardware_concurrency: 8,
      device_memory: 16,
      fuzzy_hash: "fedcba987654",
    };
    const fp2: Fingerprint = {
      ...baseFingerprint,
      hardware_concurrency: 32, // different hardware
      device_memory: 64, // different hardware
      fuzzy_hash: "111111222222", // different identity
    };

    const result1 = computeEmbedding(fp1);
    const result2 = computeEmbedding(fp2);

    // v12 includes hardware and identity — vectors should differ
    expect(result1.vector).not.toEqual(result2.vector);

    // Hardware section [267-310] should differ
    const hw1 = result1.vector.slice(267, 311);
    const hw2 = result2.vector.slice(267, 311);
    expect(hw1).not.toEqual(hw2);

    // Identity section [380-511] should differ
    const id1 = result1.vector.slice(380, 512);
    const id2 = result2.vector.slice(380, 512);
    expect(id1).not.toEqual(id2);

    // Network section [311-315] should be zeroed for both
    expect(result1.vector.slice(311, 316).every((v) => v === 0)).toBe(true);
    expect(result2.vector.slice(311, 316).every((v) => v === 0)).toBe(true);
  });

  it("zeroes rendering for Brave private mode", () => {
    const bravePrivate: Fingerprint = {
      ...baseFingerprint,
      privacy_browser: "brave",
      is_private_browsing: true,
    };
    const result = computeEmbedding(bravePrivate);

    // v12: Rendering starts at 191
    // canvas(20) + webgl(16) + audio(8) = 44 dims should be zeroed
    const randomizedSection = result.vector.slice(191, 235);
    expect(randomizedSection.every((v) => v === 0)).toBe(true);

    // clientRects(16) + gpu(16) should NOT be zeroed
    const stableSection = result.vector.slice(235, 267);
    expect(stableSection.some((v) => v !== 0)).toBe(true);
  });

  it("zeroes canvas and audio for iOS devices (all modes)", () => {
    const iosFingerprint: Fingerprint = {
      ...baseFingerprint,
      platform: "iPhone",
      user_agent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    };
    const result = computeEmbedding(iosFingerprint);

    // canvas(20) zeroed [191-210]
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.every((v) => v === 0)).toBe(true);

    // webgl(16) should be KEPT [211-226] — most stable iOS signal
    const webglSection = result.vector.slice(211, 227);
    expect(webglSection.some((v) => v !== 0)).toBe(true);

    // audio(8) zeroed [227-234]
    const audioSection = result.vector.slice(227, 235);
    expect(audioSection.every((v) => v === 0)).toBe(true);

    // clientRects(16) + gpu(16) should NOT be zeroed
    const stableSection = result.vector.slice(235, 267);
    expect(stableSection.some((v) => v !== 0)).toBe(true);
  });

  it("zeroes canvas and audio for iPad devices", () => {
    const ipadFingerprint: Fingerprint = {
      ...baseFingerprint,
      platform: "iPad",
      user_agent:
        "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    };
    const result = computeEmbedding(ipadFingerprint);

    // canvas(20) zeroed
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.every((v) => v === 0)).toBe(true);

    // audio(8) zeroed
    const audioSection = result.vector.slice(227, 235);
    expect(audioSection.every((v) => v === 0)).toBe(true);

    // webgl(16) kept
    const webglSection = result.vector.slice(211, 227);
    expect(webglSection.some((v) => v !== 0)).toBe(true);
  });

  it("zeroes canvas and webgl for macOS Safari private", () => {
    const safariPrivate: Fingerprint = {
      ...baseFingerprint,
      platform: "MacIntel",
      user_agent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
      is_private_browsing: true,
    };
    const result = computeEmbedding(safariPrivate);

    // canvas(20) zeroed [191-210]
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.every((v) => v === 0)).toBe(true);

    // webgl(16) zeroed [211-226] — differs between private/normal on macOS
    const webglSection = result.vector.slice(211, 227);
    expect(webglSection.every((v) => v === 0)).toBe(true);

    // audio(8) should be KEPT [227-234] — simhash absorbs subtle FP noise
    const audioSection = result.vector.slice(227, 235);
    expect(audioSection.some((v) => v !== 0)).toBe(true);

    // clientRects(16) + gpu(16) should NOT be zeroed
    const stableSection = result.vector.slice(235, 267);
    expect(stableSection.some((v) => v !== 0)).toBe(true);
  });

  it("zeroes canvas and webgl for standard Firefox private mode", () => {
    const firefoxPrivate: Fingerprint = {
      ...baseFingerprint,
      user_agent:
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
      is_private_browsing: true,
      privacy_browser: undefined, // standard private, NOT RFP
    };
    const result = computeEmbedding(firefoxPrivate);

    // canvas(20) zeroed [191-210]
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.every((v) => v === 0)).toBe(true);

    // webgl(16) zeroed [211-226]
    const webglSection = result.vector.slice(211, 227);
    expect(webglSection.every((v) => v === 0)).toBe(true);

    // audio(8) should be KEPT [227-234] — stable across Firefox private sessions
    const audioSection = result.vector.slice(227, 235);
    expect(audioSection.some((v) => v !== 0)).toBe(true);

    // clientRects(16) + gpu(16) should NOT be zeroed
    const stableSection = result.vector.slice(235, 267);
    expect(stableSection.some((v) => v !== 0)).toBe(true);
  });

  it("zeroes canvas and webgl for Firefox non-private (cross-mode stability)", () => {
    const firefoxNormal: Fingerprint = {
      ...baseFingerprint,
      user_agent:
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
      is_private_browsing: false,
      privacy_browser: undefined,
    };
    const result = computeEmbedding(firefoxNormal);

    // canvas(20) zeroed for all Firefox — private mode randomizes per-session
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.every((v) => v === 0)).toBe(true);

    // webgl(16) zeroed for all Firefox — pixel readback changes per-session
    const webglSection = result.vector.slice(211, 227);
    expect(webglSection.every((v) => v === 0)).toBe(true);

    // audio(8) kept — stable across Firefox sessions
    const audioSection = result.vector.slice(227, 235);
    expect(audioSection.some((v) => v !== 0)).toBe(true);
  });

  it("uses stable identity for Firefox instead of fuzzy_hash", () => {
    const firefox1: Fingerprint = {
      ...baseFingerprint,
      user_agent:
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
      fuzzy_hash: "aaaa1111bbbb2222cccc3333", // would change per session
    };
    const firefox2: Fingerprint = {
      ...firefox1,
      fuzzy_hash: "dddd4444eeee5555ffff6666", // different fuzzy_hash
    };
    const result1 = computeEmbedding(firefox1);
    const result2 = computeEmbedding(firefox2);

    // Identity section [380-511] should be IDENTICAL despite different fuzzy_hash
    const id1 = result1.vector.slice(380, 512);
    const id2 = result2.vector.slice(380, 512);
    expect(id1).toEqual(id2);
  });

  it("does not zero rendering for macOS Safari non-private", () => {
    const safariNormal: Fingerprint = {
      ...baseFingerprint,
      platform: "MacIntel",
      user_agent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
      is_private_browsing: false,
    };
    const result = computeEmbedding(safariNormal);

    // All rendering should have non-zero values
    const renderingSection = result.vector.slice(191, 267);
    expect(renderingSection.some((v) => v !== 0)).toBe(true);

    // canvas should NOT be zeroed
    const canvasSection = result.vector.slice(191, 211);
    expect(canvasSection.some((v) => v !== 0)).toBe(true);
  });
});

describe("areEmbeddingsCompatible", () => {
  it("returns true for same version and dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(512).fill(0),
      dimensions: 512,
      version: 12,
    };
    const b: EmbeddingResult = {
      vector: new Array(512).fill(0),
      dimensions: 512,
      version: 12,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(true);
  });

  it("returns false for different versions", () => {
    const a: EmbeddingResult = {
      vector: new Array(512).fill(0),
      dimensions: 512,
      version: 11,
    };
    const b: EmbeddingResult = {
      vector: new Array(512).fill(0),
      dimensions: 512,
      version: 12,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });

  it("returns false for different dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 12,
    };
    const b: EmbeddingResult = {
      vector: new Array(512).fill(0),
      dimensions: 512,
      version: 12,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });
});

describe("EMBEDDING_DIMENSIONS", () => {
  it("is 512", () => {
    expect(EMBEDDING_DIMENSIONS).toBe(512);
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
      screen_hash: "hash7",
      css_media_hash: "hash8",
      canvas_hash: "canvas",
      webgl_hash: "webgl",
      audio_hash: "audio",
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0 Chrome/120",
      platform: "Win32",
    };

    const result = assessEmbeddingQuality(fullFingerprint);
    expect(result.acceptable).toBe(true);
    expect(result.score).toBeGreaterThan(0.5);
    expect(result.structuralCount).toBe(8);
    expect(result.renderingCount).toBe(3);
    expect(result.hardwareCount).toBe(5);
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
    // 2 identity + 2 structural + 1 rendering + 2 hardware = 7 out of 18 max
    expect(result.score).toBeCloseTo(7 / 18, 2);
  });

  it("rejects when only stable_hash is present (missing fuzzy_hash)", () => {
    const fp: Fingerprint = {
      stable_hash: "abc123",
      // fuzzy_hash missing
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      user_agent: "Mozilla/5.0",
      screen_dims: "1920x1080",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(false);
    expect(result.reason).toContain("identity");
  });

  it("rejects when only fuzzy_hash is present (missing stable_hash)", () => {
    const fp: Fingerprint = {
      fuzzy_hash: "def456",
      // stable_hash missing
      maths_hash: "hash1",
      window_features_hash: "hash2",
      html_element_hash: "hash3",
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      user_agent: "Mozilla/5.0",
      screen_dims: "1920x1080",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(false);
    expect(result.reason).toContain("identity");
  });

  it("rejects with 1 structural hash (below minimum of 2)", () => {
    const fp: Fingerprint = {
      stable_hash: "abc",
      fuzzy_hash: "def",
      maths_hash: "hash1", // Only 1 structural
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      user_agent: "Mozilla/5.0",
      screen_dims: "1920x1080",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(false);
    expect(result.structuralCount).toBe(1);
    expect(result.reason).toContain("structural");
  });

  it("rejects when rendering is 0 and structural is < 4", () => {
    const fp: Fingerprint = {
      stable_hash: "abc",
      fuzzy_hash: "def",
      maths_hash: "h1",
      window_features_hash: "h2",
      html_element_hash: "h3",
      // 3 structural, 0 rendering — not enough structural to compensate
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(false);
    expect(result.structuralCount).toBe(3);
    expect(result.renderingCount).toBe(0);
    expect(result.reason).toContain("rendering");
  });

  it("accepts when rendering is 0 but structural is >= 4", () => {
    const fp: Fingerprint = {
      stable_hash: "abc",
      fuzzy_hash: "def",
      maths_hash: "h1",
      window_features_hash: "h2",
      html_element_hash: "h3",
      css_hash: "h4",
      // 4 structural, 0 rendering — structural compensates
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(true);
    expect(result.structuralCount).toBe(4);
    expect(result.renderingCount).toBe(0);
  });

  it("rejects when hardware signals are only 1 (below minimum of 2)", () => {
    const fp: Fingerprint = {
      stable_hash: "abc",
      fuzzy_hash: "def",
      maths_hash: "h1",
      window_features_hash: "h2",
      html_element_hash: "h3",
      css_hash: "h4",
      canvas_hash: "canvas",
      hardware_concurrency: 8,
      // Only 1 hardware signal (concurrency), missing memory, screen, user_agent
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(false);
    expect(result.hardwareCount).toBe(1);
    expect(result.reason).toContain("hardware");
  });

  it("accepts high-quality fingerprint with all signals", () => {
    const fp: Fingerprint = {
      stable_hash: "abc",
      fuzzy_hash: "def",
      maths_hash: "h1",
      window_features_hash: "h2",
      html_element_hash: "h3",
      css_hash: "h4",
      svg_hash: "h5",
      intl_hash: "h6",
      screen_hash: "h7",
      css_media_hash: "h8",
      canvas_hash: "canvas",
      webgl_hash: "webgl",
      audio_hash: "audio",
      hardware_concurrency: 8,
      device_memory: 16,
      screen_dims: "1920x1080",
      user_agent: "Mozilla/5.0 Chrome/120",
      platform: "Win32",
    };

    const result = assessEmbeddingQuality(fp);
    expect(result.acceptable).toBe(true);
    expect(result.score).toBe(1.0);
    expect(result.structuralCount).toBe(8);
    expect(result.renderingCount).toBe(3);
    expect(result.hardwareCount).toBe(5);
    expect(result.reason).toBeUndefined();
  });
});

describe("computeWeightedEmbedding", () => {
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
    timezone: "America/New_York",
    is_private_browsing: false,
    is_headless: false,
    lie_count: 0,
    features_hash: "aabbccdd",
  };

  it("produces 512 dimensions", () => {
    const weights = new Array(512).fill(2.0);
    const result = computeWeightedEmbedding(baseFingerprint, weights);
    expect(result.vector).toHaveLength(EMBEDDING_DIMENSIONS);
    expect(result.dimensions).toBe(EMBEDDING_DIMENSIONS);
  });

  it("returns version 13", () => {
    const weights = new Array(512).fill(1.0);
    const result = computeWeightedEmbedding(baseFingerprint, weights);
    expect(result.version).toBe(WEIGHTED_EMBEDDING_VERSION);
    expect(result.version).toBe(13);
  });

  it("with all-ones weights equals computeEmbedding", () => {
    const allOnes = new Array(512).fill(1.0);
    const base = computeEmbedding(baseFingerprint);
    const weighted = computeWeightedEmbedding(baseFingerprint, allOnes);
    expect(weighted.vector).toEqual(base.vector);
  });

  it("applies element-wise multiplication", () => {
    const base = computeEmbedding(baseFingerprint);
    const weights = new Array(512).fill(1.0);
    weights[0] = 3.0;
    weights[100] = 0.5;
    weights[198] = 0;

    const result = computeWeightedEmbedding(baseFingerprint, weights);
    expect(result.vector[0]).toBeCloseTo(base.vector[0] * 3.0);
    expect(result.vector[100]).toBeCloseTo(base.vector[100] * 0.5);
    expect(result.vector[198]).toBe(0);
    // Unweighted dims should be unchanged
    expect(result.vector[50]).toBeCloseTo(base.vector[50]);
  });

  it("zeroing a weight zeroes that dimension", () => {
    const weights = new Array(512).fill(1.0);
    weights[227] = 0; // audio section
    const result = computeWeightedEmbedding(baseFingerprint, weights);
    expect(result.vector[227]).toBeCloseTo(0);
  });

  it("is deterministic", () => {
    const weights = new Array(512).fill(1.5);
    const a = computeWeightedEmbedding(baseFingerprint, weights);
    const b = computeWeightedEmbedding(baseFingerprint, weights);
    expect(a.vector).toEqual(b.vector);
  });
});
