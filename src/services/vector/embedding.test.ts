/**
 * @fileoverview Tests for fingerprint embedding service.
 */

import { describe, it, expect } from "vitest";
import {
  computeEmbedding,
  EMBEDDING_DIMENSIONS,
  EMBEDDING_VERSION,
  areEmbeddingsCompatible,
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
    expect(result.version).toBe(3);
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
    // Hardware section starts at 96, first few values are normalized numerics
    const hwConcurrency = result.vector[96];
    const deviceMemory = result.vector[97];
    expect(hwConcurrency).toBeGreaterThanOrEqual(0);
    expect(hwConcurrency).toBeLessThanOrEqual(1);
    expect(deviceMemory).toBeGreaterThanOrEqual(0);
    expect(deviceMemory).toBeLessThanOrEqual(1);
  });

  it("pads remaining dimensions with zeros", () => {
    const result = computeEmbedding(baseFingerprint);
    // Reserved section (198-255) should be zeros
    // Structure: 48+48+32+32+22+16 = 198 used dims
    const reserved = result.vector.slice(198);
    expect(reserved.every((v) => v === 0)).toBe(true);
  });
});

describe("areEmbeddingsCompatible", () => {
  it("returns true for same version and dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 3,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 3,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(true);
  });

  it("returns false for different versions", () => {
    const a: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 2,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 3,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });

  it("returns false for different dimensions", () => {
    const a: EmbeddingResult = {
      vector: new Array(128).fill(0),
      dimensions: 128,
      version: 3,
    };
    const b: EmbeddingResult = {
      vector: new Array(256).fill(0),
      dimensions: 256,
      version: 3,
    };
    expect(areEmbeddingsCompatible(a, b)).toBe(false);
  });
});

describe("EMBEDDING_DIMENSIONS", () => {
  it("is 256", () => {
    expect(EMBEDDING_DIMENSIONS).toBe(256);
  });
});
