// src/services/get-api-keys-secret.test.ts
// AR-131: Tests for API keys Secrets Manager fetching with caching
import {
  describe,
  it,
  expect,
  beforeEach,
  afterAll,
  vi,
  afterEach,
} from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { ERROR_STRINGS } from "../helpers/constants";

const secretsManagerMock = mockClient(SecretsManagerClient);

// Mock the constants module to control API_KEYS_SECRET_ARN
const mockSecretArn =
  "arn:aws:secretsmanager:us-east-1:123456789:secret:argus-api-keys";
let mockApiKeysSecretArn: string | undefined = mockSecretArn;

vi.mock("../helpers/constants", async () => {
  const actual = await vi.importActual("../helpers/constants");
  return {
    ...actual,
    get API_KEYS_SECRET_ARN() {
      return mockApiKeysSecretArn;
    },
    API_KEYS_CACHE_TTL: 1000 * 60 * 5, // 5 minutes
  };
});

// Import after mocking
import {
  getApiKeysSecret,
  initApiKeysSecret,
  clearApiKeysCache,
  resetClient,
} from "./get-api-keys-secret";

describe("getApiKeysSecret (AR-131)", () => {
  beforeEach(() => {
    secretsManagerMock.reset();
    clearApiKeysCache();
    resetClient();
    mockApiKeysSecretArn = mockSecretArn;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  afterAll(() => {
    secretsManagerMock.restore();
  });

  describe("successful retrieval", () => {
    it("should fetch API keys from Secrets Manager", async () => {
      const mockApiKeys = {
        sk_live_abc123: "tenant-1",
        sk_live_def456: "tenant-2",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      const result = await getApiKeysSecret();

      expect(result).toEqual({
        sk_live_abc123: "tenant-1",
        sk_live_def456: "tenant-2",
      });
    });

    it("should return empty object when no ARN is configured", async () => {
      mockApiKeysSecretArn = undefined;

      const result = await getApiKeysSecret();

      expect(result).toEqual({});
      // Should not call Secrets Manager
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(0);
    });
  });

  describe("caching behavior", () => {
    it("should cache API keys and not call Secrets Manager again within TTL", async () => {
      const mockApiKeys = {
        sk_live_cached: "tenant-cached",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      // First call - should hit Secrets Manager
      const result1 = await getApiKeysSecret();
      expect(result1["sk_live_cached"]).toBe("tenant-cached");

      // Second call - should use cache
      const result2 = await getApiKeysSecret();
      expect(result2["sk_live_cached"]).toBe("tenant-cached");

      // Verify Secrets Manager was only called once
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);
    });

    it("should refresh cache after TTL expires", async () => {
      vi.useFakeTimers();

      const mockApiKeys = {
        sk_live_initial: "tenant-initial",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      // First call - populate cache
      await getApiKeysSecret();
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);

      // Advance time past 5 minute TTL
      vi.advanceTimersByTime(1000 * 60 * 5 + 1);

      // Update mock to return new keys
      const updatedKeys = {
        sk_live_updated: "tenant-updated",
      };
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(updatedKeys),
      });

      // Second call - should refresh from Secrets Manager
      const result = await getApiKeysSecret();
      expect(result["sk_live_updated"]).toBe("tenant-updated");
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(2);

      vi.useRealTimers();
    });
  });

  describe("clearApiKeysCache", () => {
    it("should clear the cached API keys", async () => {
      const mockApiKeys = {
        sk_live_clear: "tenant-clear",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      // First call - populate cache
      await getApiKeysSecret();
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);

      // Clear cache
      clearApiKeysCache();

      // Second call - should hit Secrets Manager again
      await getApiKeysSecret();
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(2);
    });
  });

  describe("error handling", () => {
    it("should throw error when initApiKeysSecret fails (fail closed)", async () => {
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects(new Error("AWS error"));

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });

    it("should throw error when secret not found", async () => {
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects(new Error("Secret not found"));

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });

    it("should throw error when secret JSON is malformed", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: "not-valid-json",
      });

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });

    it("should throw error when SecretString is null/undefined", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: undefined,
      });

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });

    it("should throw error when API_KEYS_SECRET_ARN is not set during init", async () => {
      mockApiKeysSecretArn = undefined;

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_ARN_NOT_SET,
      );
    });
  });

  describe("graceful degradation (stale cache)", () => {
    it("should use stale cache when refresh fails after successful init", async () => {
      vi.useFakeTimers();

      const mockApiKeys = {
        sk_live_stale: "tenant-stale",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      // Initial fetch - populate cache
      await getApiKeysSecret();

      // Advance time past TTL
      vi.advanceTimersByTime(1000 * 60 * 5 + 1);

      // Make refresh fail
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects(new Error("Temporary failure"));

      // Should return stale cached value instead of throwing
      const result = await getApiKeysSecret();
      expect(result["sk_live_stale"]).toBe("tenant-stale");

      vi.useRealTimers();
    });
  });

  describe("initApiKeysSecret", () => {
    it("should fetch and cache API keys at init", async () => {
      const mockApiKeys = {
        sk_live_init: "tenant-init",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      const result = await initApiKeysSecret();

      expect(result).toEqual({ sk_live_init: "tenant-init" });
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);
    });

    it("should return cached keys on subsequent init calls", async () => {
      const mockApiKeys = {
        sk_live_multi: "tenant-multi",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockApiKeys),
      });

      // Multiple init calls should only fetch once
      await initApiKeysSecret();
      await initApiKeysSecret();
      await initApiKeysSecret();

      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);
    });
  });

  describe("validation", () => {
    it("should reject array format for API keys", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(["key1", "key2"]),
      });

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });

    it("should reject non-string values in API keys", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify({ sk_live_bad: 12345 }),
      });

      await expect(initApiKeysSecret()).rejects.toThrow(
        ERROR_STRINGS.API_KEYS_FETCH_FAILED,
      );
    });
  });
});
