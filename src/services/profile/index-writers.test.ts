// src/services/profile/index-writers.test.ts
// AR-150: Tests for tier-gated identity association

import { describe, it, expect } from "vitest";
import {
  buildTier1IndexEntries,
  buildIdentityIndexEntries,
  buildHashIndexEntries,
  ASSOCIATION_ALLOWED_EVIDENCE,
} from "./index-writers";
import { Fingerprint } from "./types";

describe("AR-150: Tier-gated identity association", () => {
  const ttl = 1705000000;

  describe("ASSOCIATION_ALLOWED_EVIDENCE", () => {
    it("should contain Tier 0.5 identity codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("PUBLIC_KEY_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("EVERCOOKIE_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("SIGINT_ID_MATCH");
    });

    it("should contain Tier 1 hash codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("STABLE_HASH_MATCH");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("FUZZY_HASH_MATCH");
    });

    it("should contain time-bounded anchor codes", () => {
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("SESSION_ANCHOR_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("IP_UA_ANCHOR_BUCKET");
    });

    it("should NOT contain unbounded Tier 2 bucket codes", () => {
      // These are the viral spreading culprits
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("IP_JA4_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain(
        "GPU_SCREEN_TZ_BUCKET",
      );
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("AUDIO_CANVAS_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("MATHS_WINDOW_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("HTML_CSS_BUCKET");
      expect(ASSOCIATION_ALLOWED_EVIDENCE).not.toContain("WEBGL_STRUCT_BUCKET");
    });

    it("should contain NEW_DEVICE code", () => {
      // New devices must create indexes for future lookups to work
      expect(ASSOCIATION_ALLOWED_EVIDENCE).toContain("NEW_DEVICE");
    });
  });

  describe("buildIdentityIndexEntries", () => {
    it("should return empty array when no identity fields present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);
      expect(entries).toEqual([]);
    });

    it("should build pubkey# entry for public_key", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = { public_key: publicKey };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: `pubkey#${publicKey}`,
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build evercookie# entry for evercookie_id", () => {
      const fingerprint: Fingerprint = { evercookie_id: "cookie123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "evercookie#cookie123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build sigint# entry for sigint_id", () => {
      const fingerprint: Fingerprint = { sigint_id: "sigint-uuid-123" };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "sigint#sigint-uuid-123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build all identity entries when all identity fields present", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        // Hash fields should be ignored
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(3);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain(`pubkey#${publicKey}`);
      expect(hashKeys).toContain("evercookie#cookie123");
      expect(hashKeys).toContain("sigint#sigint-uuid-123");
      // Should NOT contain hash entries
      expect(hashKeys).not.toContain("stable#stable123");
      expect(hashKeys).not.toContain("fuzzy#fuzzy456");
    });
  });

  describe("buildHashIndexEntries", () => {
    it("should return empty array when no hash fields present", () => {
      const fingerprint: Fingerprint = {
        public_key: "MFkwE...",
        evercookie_id: "cookie123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);
      expect(entries).toEqual([]);
    });

    it("should build stable# entry for stable_hash", () => {
      const fingerprint: Fingerprint = { stable_hash: "stable123" };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "stable#stable123",
        device_id: "dev_123",
        ttl,
      });
    });

    it("should build fuzzy# entry for fuzzy_hash", () => {
      const fingerprint: Fingerprint = { fuzzy_hash: "fuzzy456" };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual({
        hash_key: "fuzzy#fuzzy456",
        device_id: "dev_123",
        fuzzy_hash: "fuzzy456", // AR-XXX: Now included for drift detection
        ttl,
      });
    });

    it("should build all hash entries when all hash fields present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
        // Identity fields should be ignored
        public_key: "MFkwE...",
        evercookie_id: "cookie123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain("stable#stable123");
      expect(hashKeys).toContain("fuzzy#fuzzy456");
      // Should NOT contain identity entries
      expect(hashKeys).not.toContain("pubkey#MFkwE...");
      expect(hashKeys).not.toContain("evercookie#cookie123");
    });
  });

  describe("buildTier1IndexEntries (backward compatibility)", () => {
    it("should still return all entries for full fingerprint", () => {
      const publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...";
      const fingerprint: Fingerprint = {
        public_key: publicKey,
        evercookie_id: "cookie123",
        sigint_id: "sigint-uuid-123",
        stable_hash: "stable123",
        fuzzy_hash: "fuzzy456",
      };
      const entries = buildTier1IndexEntries("dev_123", fingerprint, ttl);

      // Should return all 5 entries
      expect(entries).toHaveLength(5);
      const hashKeys = entries.map((e) => e.hash_key);
      expect(hashKeys).toContain(`pubkey#${publicKey}`);
      expect(hashKeys).toContain("evercookie#cookie123");
      expect(hashKeys).toContain("sigint#sigint-uuid-123");
      expect(hashKeys).toContain("stable#stable123");
      expect(hashKeys).toContain("fuzzy#fuzzy456");
    });
  });

  describe("AR-XXX: fuzzy_hash in index entries for drift detection", () => {
    it("should include fuzzy_hash in buildTier1IndexEntries", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        stable_hash: "stable123",
        fuzzy_hash: "0123456789abcdef",
      };
      const entries = buildTier1IndexEntries("dev_123", fingerprint, ttl);

      // All entries should include the fuzzy_hash
      expect(entries).toHaveLength(3);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("0123456789abcdef");
      });
    });

    it("should include fuzzy_hash in buildIdentityIndexEntries", () => {
      const fingerprint: Fingerprint = {
        evercookie_id: "cookie123",
        public_key: "pubkey123",
        fuzzy_hash: "fedcba9876543210",
      };
      const entries = buildIdentityIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("fedcba9876543210");
      });
    });

    it("should include fuzzy_hash in buildHashIndexEntries", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
        fuzzy_hash: "abcd1234efgh5678",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(2);
      entries.forEach((entry) => {
        expect(entry.fuzzy_hash).toBe("abcd1234efgh5678");
      });
    });

    it("should include undefined fuzzy_hash when not present", () => {
      const fingerprint: Fingerprint = {
        stable_hash: "stable123",
      };
      const entries = buildHashIndexEntries("dev_123", fingerprint, ttl);

      expect(entries).toHaveLength(1);
      expect(entries[0].fuzzy_hash).toBeUndefined();
    });
  });
});
