// src/services/get-aws-secrets.test.ts
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

// Mock the constants module to control SECRET_KEY_ARN
const mockSecretArn =
  "arn:aws:secretsmanager:us-east-1:123456789:secret:argus-keys";
let mockSecretKeyArn: string | undefined = mockSecretArn;

vi.mock("../helpers/constants", async () => {
  const actual = await vi.importActual("../helpers/constants");
  return {
    ...actual,
    get SECRET_KEY_ARN() {
      return mockSecretKeyArn;
    },
  };
});

// Import after mocking
import {
  getAwsSecrets,
  getVersionedSecrets,
  clearCache,
} from "./get-aws-secrets";

describe("getAwsSecrets", () => {
  beforeEach(() => {
    // Reset mocks and cache before each test
    secretsManagerMock.reset();
    clearCache();
    mockSecretKeyArn = mockSecretArn;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  afterAll(() => {
    secretsManagerMock.restore();
  });

  describe("successful retrieval", () => {
    it("should retrieve secrets from Secrets Manager", async () => {
      const mockSecrets = {
        ENCRYPTION_KEY: "test-encryption-key",
        HMAC_KEY: "test-hmac-key",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockSecrets),
      });

      const result = await getAwsSecrets();

      expect(result).toEqual({
        ENCRYPTION_KEY: "test-encryption-key",
        HMAC_KEY: "test-hmac-key",
      });
    });

    it("should only extract required keys from secrets", async () => {
      const mockSecrets = {
        ENCRYPTION_KEY: "enc-key",
        HMAC_KEY: "hmac-key",
        EXTRA_KEY: "should-be-ignored",
        ANOTHER_KEY: "also-ignored",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockSecrets),
      });

      const result = await getAwsSecrets();

      expect(result).toEqual({
        ENCRYPTION_KEY: "enc-key",
        HMAC_KEY: "hmac-key",
      });
      expect(result).not.toHaveProperty("EXTRA_KEY");
      expect(result).not.toHaveProperty("ANOTHER_KEY");
    });
  });

  describe("caching behavior", () => {
    it("should cache secrets and not call Secrets Manager again within cache duration", async () => {
      const mockSecrets = {
        ENCRYPTION_KEY: "cached-key",
        HMAC_KEY: "cached-hmac",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockSecrets),
      });

      // First call - should hit Secrets Manager
      const result1 = await getAwsSecrets();
      expect(result1.ENCRYPTION_KEY).toBe("cached-key");

      // Second call - should use cache
      const result2 = await getAwsSecrets();
      expect(result2.ENCRYPTION_KEY).toBe("cached-key");

      // Verify Secrets Manager was only called once
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);
    });
  });

  describe("clearCache", () => {
    it("should clear the cached secrets", async () => {
      const mockSecrets = {
        ENCRYPTION_KEY: "cached-key",
        HMAC_KEY: "cached-hmac",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockSecrets),
      });

      // First call - populate cache
      await getAwsSecrets();
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(1);

      // Clear cache
      clearCache();

      // Second call - should hit Secrets Manager again
      await getAwsSecrets();
      expect(
        secretsManagerMock.commandCalls(GetSecretValueCommand),
      ).toHaveLength(2);
    });
  });

  describe("error handling", () => {
    it("should throw error when SECRET_KEY_ARN is not set", async () => {
      mockSecretKeyArn = undefined;

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.KEY_ARN_NOT_SET,
      );
    });

    it("should throw error when required keys are missing", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify({ ENCRYPTION_KEY: "only-one-key" }),
      });

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.SECRETS_MANAGER_FAILED,
      );
    });

    it("should throw error when all required keys are missing", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify({ UNRELATED_KEY: "value" }),
      });

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.SECRETS_MANAGER_FAILED,
      );
    });

    it("should throw error when Secrets Manager call fails", async () => {
      secretsManagerMock
        .on(GetSecretValueCommand)
        .rejects(new Error("AWS error"));

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.SECRETS_MANAGER_FAILED,
      );
    });

    it("should throw error when SecretString is not valid JSON", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: "not-valid-json",
      });

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.SECRETS_MANAGER_FAILED,
      );
    });

    it("should throw error when SecretString is null", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: undefined,
      });

      await expect(getAwsSecrets()).rejects.toThrow(
        ERROR_STRINGS.SECRETS_MANAGER_FAILED,
      );
    });
  });

  describe("versioned secrets (AR-28)", () => {
    it("should handle versioned format with current and previous keys", async () => {
      const versionedSecrets = {
        version: 2,
        current: {
          ENCRYPTION_KEY: "current-enc-key",
          HMAC_KEY: "current-hmac-key",
        },
        previous: {
          ENCRYPTION_KEY: "previous-enc-key",
          HMAC_KEY: "previous-hmac-key",
        },
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(versionedSecrets),
      });

      const result = await getVersionedSecrets();

      expect(result.version).toBe(2);
      expect(result.current.ENCRYPTION_KEY).toBe("current-enc-key");
      expect(result.current.HMAC_KEY).toBe("current-hmac-key");
      expect(result.previous?.ENCRYPTION_KEY).toBe("previous-enc-key");
      expect(result.previous?.HMAC_KEY).toBe("previous-hmac-key");
    });

    it("should handle versioned format without previous keys", async () => {
      const versionedSecrets = {
        version: 1,
        current: {
          ENCRYPTION_KEY: "enc-key",
          HMAC_KEY: "hmac-key",
        },
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(versionedSecrets),
      });

      const result = await getVersionedSecrets();

      expect(result.version).toBe(1);
      expect(result.current.ENCRYPTION_KEY).toBe("enc-key");
      expect(result.previous).toBeUndefined();
    });

    it("should convert legacy format to versioned format", async () => {
      const legacySecrets = {
        ENCRYPTION_KEY: "legacy-enc-key",
        HMAC_KEY: "legacy-hmac-key",
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(legacySecrets),
      });

      const result = await getVersionedSecrets();

      expect(result.version).toBe(1);
      expect(result.current.ENCRYPTION_KEY).toBe("legacy-enc-key");
      expect(result.current.HMAC_KEY).toBe("legacy-hmac-key");
      expect(result.previous).toBeUndefined();
    });

    it("getAwsSecrets should return flat format from versioned secrets", async () => {
      const versionedSecrets = {
        version: 3,
        current: {
          ENCRYPTION_KEY: "versioned-enc-key",
          HMAC_KEY: "versioned-hmac-key",
        },
        previous: {
          ENCRYPTION_KEY: "old-enc-key",
          HMAC_KEY: "old-hmac-key",
        },
      };

      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(versionedSecrets),
      });

      const result = await getAwsSecrets();

      // Should only return current keys in flat format
      expect(result).toEqual({
        ENCRYPTION_KEY: "versioned-enc-key",
        HMAC_KEY: "versioned-hmac-key",
      });
      expect(result).not.toHaveProperty("previous");
    });
  });
});
