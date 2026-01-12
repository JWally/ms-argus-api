// src/services/rotate-aws-secrets.test.ts
import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecretsManagerClient,
  PutSecretValueCommand,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { handler } from "./rotate-aws-secrets";

const secretsManagerMock = mockClient(SecretsManagerClient);

// Helper to create legacy secret mock
const mockLegacySecret = {
  ENCRYPTION_KEY: "old-enc-key-base64",
  HMAC_KEY: "old-hmac-key-base64",
};

// Helper to create versioned secret mock
const mockVersionedSecret = {
  version: 2,
  current: {
    ENCRYPTION_KEY: "current-enc-key-base64",
    HMAC_KEY: "current-hmac-key-base64",
  },
  previous: {
    ENCRYPTION_KEY: "previous-enc-key-base64",
    HMAC_KEY: "previous-hmac-key-base64",
  },
};

describe("rotate-aws-secrets handler", () => {
  const originalEnv = process.env;
  const validSecretArn =
    "arn:aws:secretsmanager:us-east-1:123456789:secret:argus-keys";

  beforeEach(() => {
    secretsManagerMock.reset();
    process.env = { ...originalEnv };
    process.env.SECRET_ARN = validSecretArn;
  });

  afterAll(() => {
    process.env = originalEnv;
    secretsManagerMock.restore();
  });

  describe("successful rotation", () => {
    it("should rotate secrets successfully", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await expect(handler()).resolves.not.toThrow();
    });

    it("should call PutSecretValueCommand with correct SecretId", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input.SecretId).toBe(validSecretArn);
    });

    it("should generate new versioned secret structure (AR-28)", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      // New versioned structure
      expect(secrets).toHaveProperty("version", 2); // 1 (legacy) + 1
      expect(secrets).toHaveProperty("current");
      expect(secrets.current).toHaveProperty("ENCRYPTION_KEY");
      expect(secrets.current).toHaveProperty("HMAC_KEY");
      expect(secrets).toHaveProperty("previous");
      expect(secrets).toHaveProperty("rotatedAt");
    });

    it("should preserve previous keys during rotation (AR-28)", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets = JSON.parse(calls[0].args[0].input.SecretString!);

      // Previous should contain the old keys
      expect(secrets.previous.ENCRYPTION_KEY).toBe(
        mockLegacySecret.ENCRYPTION_KEY,
      );
      expect(secrets.previous.HMAC_KEY).toBe(mockLegacySecret.HMAC_KEY);
    });

    it("should increment version when rotating versioned secret", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockVersionedSecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets = JSON.parse(calls[0].args[0].input.SecretString!);

      expect(secrets.version).toBe(3); // 2 + 1
      expect(secrets.previous.ENCRYPTION_KEY).toBe(
        mockVersionedSecret.current.ENCRYPTION_KEY,
      );
    });

    it("should generate base64 encoded 256-bit keys", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      // Base64 encoded 32 bytes = 44 characters (with padding)
      expect(secrets.current.ENCRYPTION_KEY).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(secrets.current.HMAC_KEY).toMatch(/^[A-Za-z0-9+/]+=*$/);

      // Verify they decode to 32 bytes
      const encKeyBuffer = Buffer.from(
        secrets.current.ENCRYPTION_KEY,
        "base64",
      );
      const hmacKeyBuffer = Buffer.from(secrets.current.HMAC_KEY, "base64");
      expect(encKeyBuffer.length).toBe(32);
      expect(hmacKeyBuffer.length).toBe(32);
    });

    it("should include ISO timestamp in rotatedAt", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      // Verify rotatedAt is a valid ISO date string
      const rotatedAt = new Date(secrets.rotatedAt);
      expect(rotatedAt.toISOString()).toBe(secrets.rotatedAt);
    });

    it("should generate unique keys on each rotation", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      // First rotation
      await handler();
      const calls1 = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets1 = JSON.parse(calls1[0].args[0].input.SecretString!);

      // Reset mock for second rotation (return the result of first rotation)
      secretsManagerMock.reset();
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(secrets1),
      });
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      // Second rotation
      await handler();
      const calls2 = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets2 = JSON.parse(calls2[0].args[0].input.SecretString!);

      // Keys should be different
      expect(secrets1.current.ENCRYPTION_KEY).not.toBe(
        secrets2.current.ENCRYPTION_KEY,
      );
      expect(secrets1.current.HMAC_KEY).not.toBe(secrets2.current.HMAC_KEY);
    });
  });

  describe("error handling", () => {
    it("should throw error when SECRET_ARN is not set", async () => {
      delete process.env.SECRET_ARN;

      await expect(handler()).rejects.toThrow(
        "SECRET_ARN environment variable is not set",
      );
    });

    it("should throw error when SECRET_ARN is empty string", async () => {
      process.env.SECRET_ARN = "";

      await expect(handler()).rejects.toThrow(
        "SECRET_ARN environment variable is not set",
      );
    });

    it("should throw error when GetSecretValueCommand fails", async () => {
      const awsError = new Error("Access denied");
      secretsManagerMock.on(GetSecretValueCommand).rejects(awsError);

      await expect(handler()).rejects.toThrow("Access denied");
    });

    it("should throw error when PutSecretValueCommand fails", async () => {
      secretsManagerMock.on(GetSecretValueCommand).resolves({
        SecretString: JSON.stringify(mockLegacySecret),
      });
      const awsError = new Error("Access denied");
      secretsManagerMock.on(PutSecretValueCommand).rejects(awsError);

      await expect(handler()).rejects.toThrow("Access denied");
    });
  });
});
