// src/services/profile/drift-detection.test.ts
// AR-168: Unit tests for drift detection logic
import { describe, it, expect } from "vitest";
import { hasSignificantDrift } from "./drift-detection";
import { DeviceProfile, Fingerprint } from "./types";

// Helper to create a base profile with common fields
function createBaseProfile(): DeviceProfile {
  return {
    device_id: "dev_test123",
    stable_hash: "stable_abc",
    fuzzy_hash: "fuzzy_xyz",
    canvas_hash: "canvas_123",
    webgl_hash: "webgl_456",
    audio_hash: "audio_789",
    gpu_renderer: "NVIDIA GeForce GTX 1080",
    screen_dims: "1920x1080",
    first_seen_at: Date.now() - 86400000,
    last_seen_at: Date.now(),
    request_count: 10,
    risk_score: 0,
    flags: [],
    updated_at: Date.now(),
    ttl: Math.floor(Date.now() / 1000) + 86400 * 60, // 60 days
  };
}

// Helper to create a base fingerprint matching the profile
function createMatchingFingerprint(): Fingerprint {
  return {
    stable_hash: "stable_abc",
    fuzzy_hash: "fuzzy_xyz",
    canvas_hash: "canvas_123",
    webgl_hash: "webgl_456",
    audio_hash: "audio_789",
    gpu_renderer: "NVIDIA GeForce GTX 1080",
    screen_dims: "1920x1080",
  };
}

describe("hasSignificantDrift", () => {
  describe("stable_hash changes (major drift)", () => {
    it("should return true when stable_hash is different", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.stable_hash = "stable_different";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should return true when stable_hash changes even if all other signals match", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.stable_hash = "new_stable_hash";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });
  });

  describe("no drift (identical signals)", () => {
    it("should return false when all signals match", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });
  });

  describe("single signal changes (below threshold)", () => {
    it("should return false when only canvas_hash changes", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = "canvas_new";

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });

    it("should return false when only webgl_hash changes", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.webgl_hash = "webgl_new";

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });

    it("should return false when only audio_hash changes", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.audio_hash = "audio_new";

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });

    it("should return false when only gpu_renderer changes", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.gpu_renderer = "AMD Radeon RX 580";

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });

    it("should return false when only screen_dims changes", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.screen_dims = "2560x1440";

      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });
  });

  describe("two signal changes (at threshold)", () => {
    it("should return true when canvas_hash and webgl_hash change", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = "canvas_new";
      incoming.webgl_hash = "webgl_new";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should return true when audio_hash and gpu_renderer change", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.audio_hash = "audio_new";
      incoming.gpu_renderer = "Intel UHD Graphics 630";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should return true when screen_dims and canvas_hash change", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.screen_dims = "3840x2160";
      incoming.canvas_hash = "canvas_4k";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });
  });

  describe("multiple signal changes (above threshold)", () => {
    it("should return true when three signals change", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = "canvas_new";
      incoming.webgl_hash = "webgl_new";
      incoming.audio_hash = "audio_new";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should return true when all five signals change", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = "canvas_new";
      incoming.webgl_hash = "webgl_new";
      incoming.audio_hash = "audio_new";
      incoming.gpu_renderer = "Apple M1";
      incoming.screen_dims = "2560x1600";

      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });
  });

  describe("edge cases with undefined values", () => {
    it("should handle undefined values in existing profile", () => {
      const existing = createBaseProfile();
      existing.canvas_hash = undefined;
      existing.webgl_hash = undefined;
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = "canvas_new";
      incoming.webgl_hash = "webgl_new";

      // undefined !== "canvas_new" counts as changed
      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should handle undefined values in incoming fingerprint", () => {
      const existing = createBaseProfile();
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = undefined;
      incoming.webgl_hash = undefined;

      // "canvas_123" !== undefined counts as changed
      expect(hasSignificantDrift(existing, incoming)).toBe(true);
    });

    it("should return false when both have matching undefined values", () => {
      const existing = createBaseProfile();
      existing.canvas_hash = undefined;
      const incoming = createMatchingFingerprint();
      incoming.canvas_hash = undefined;

      // undefined === undefined is not a change
      expect(hasSignificantDrift(existing, incoming)).toBe(false);
    });
  });
});
