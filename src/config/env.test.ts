// src/config/env.test.ts
// AR-52: Updated to use SESSION_CACHE_TABLE instead of REDIS_ENDPOINT
import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { getMatchingWorkerEnv, getProfileUpdaterEnv } from "./env";

describe("Environment validation", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset process.env before each test
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    // Restore original env after all tests
    process.env = originalEnv;
  });

  describe("getMatchingWorkerEnv", () => {
    const requiredVars = {
      SESSION_CACHE_TABLE: "session-cache-table",
      PROFILES_TABLE: "profiles-table",
      TIER1_INDEX_TABLE: "tier1-index-table",
      TIER2_BUCKETS_TABLE: "tier2-buckets-table",
      PROFILE_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123/queue",
    };

    it("should return validated config when all required vars are present", () => {
      Object.assign(process.env, requiredVars);

      const config = getMatchingWorkerEnv();

      expect(config.SESSION_CACHE_TABLE).toBe("session-cache-table");
      expect(config.PROFILES_TABLE).toBe("profiles-table");
      expect(config.TIER1_INDEX_TABLE).toBe("tier1-index-table");
      expect(config.TIER2_BUCKETS_TABLE).toBe("tier2-buckets-table");
      expect(config.PROFILE_QUEUE_URL).toBe(
        "https://sqs.us-east-1.amazonaws.com/123/queue",
      );
      expect(config.POWERTOOLS_SERVICE_NAME).toBe("argus-matching"); // default
      expect(config.POWERTOOLS_METRICS_NAMESPACE).toBe("Argus"); // default
    });

    it("should use custom Powertools config when provided", () => {
      Object.assign(process.env, requiredVars, {
        POWERTOOLS_SERVICE_NAME: "custom-service",
        POWERTOOLS_METRICS_NAMESPACE: "CustomNamespace",
      });

      const config = getMatchingWorkerEnv();

      expect(config.POWERTOOLS_SERVICE_NAME).toBe("custom-service");
      expect(config.POWERTOOLS_METRICS_NAMESPACE).toBe("CustomNamespace");
    });

    it("should throw error listing all missing required vars", () => {
      // Clear all required vars
      delete process.env.SESSION_CACHE_TABLE;
      delete process.env.PROFILES_TABLE;
      delete process.env.TIER1_INDEX_TABLE;
      delete process.env.TIER2_BUCKETS_TABLE;
      delete process.env.PROFILE_QUEUE_URL;

      expect(() => getMatchingWorkerEnv()).toThrow(
        "Missing required environment variables: SESSION_CACHE_TABLE, PROFILES_TABLE, TIER1_INDEX_TABLE, TIER2_BUCKETS_TABLE, PROFILE_QUEUE_URL",
      );
    });

    it("should throw error for single missing var", () => {
      Object.assign(process.env, requiredVars);
      delete process.env.PROFILE_QUEUE_URL;

      expect(() => getMatchingWorkerEnv()).toThrow(
        "Missing required environment variables: PROFILE_QUEUE_URL",
      );
    });
  });

  describe("getProfileUpdaterEnv", () => {
    const requiredVars = {
      SESSION_CACHE_TABLE: "session-cache-table",
      PROFILES_TABLE: "profiles-table",
      TIER1_INDEX_TABLE: "tier1-index-table",
      TIER2_BUCKETS_TABLE: "tier2-buckets-table",
    };

    it("should return validated config when all required vars are present", () => {
      Object.assign(process.env, requiredVars);

      const config = getProfileUpdaterEnv();

      expect(config.SESSION_CACHE_TABLE).toBe("session-cache-table");
      expect(config.PROFILES_TABLE).toBe("profiles-table");
      expect(config.TIER1_INDEX_TABLE).toBe("tier1-index-table");
      expect(config.TIER2_BUCKETS_TABLE).toBe("tier2-buckets-table");
      expect(config.POWERTOOLS_SERVICE_NAME).toBe("argus-profile"); // default
      expect(config.POWERTOOLS_METRICS_NAMESPACE).toBe("Argus"); // default
    });

    it("should throw error listing all missing required vars", () => {
      delete process.env.SESSION_CACHE_TABLE;
      delete process.env.PROFILES_TABLE;
      delete process.env.TIER1_INDEX_TABLE;
      delete process.env.TIER2_BUCKETS_TABLE;

      expect(() => getProfileUpdaterEnv()).toThrow(
        "Missing required environment variables: SESSION_CACHE_TABLE, PROFILES_TABLE, TIER1_INDEX_TABLE, TIER2_BUCKETS_TABLE",
      );
    });

    it("should not require PROFILE_QUEUE_URL (unlike matching worker)", () => {
      Object.assign(process.env, requiredVars);
      delete process.env.PROFILE_QUEUE_URL;

      // Should not throw - PROFILE_QUEUE_URL is not required for ProfileUpdater
      expect(() => getProfileUpdaterEnv()).not.toThrow();
    });
  });
});
