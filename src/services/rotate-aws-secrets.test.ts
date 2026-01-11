// src/services/rotate-aws-secrets.test.ts
import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecretsManagerClient,
  PutSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { handler } from "./rotate-aws-secrets";

const secretsManagerMock = mockClient(SecretsManagerClient);

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
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await expect(handler()).resolves.not.toThrow();
    });

    it("should call PutSecretValueCommand with correct SecretId", async () => {
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      expect(calls).toHaveLength(1);
      expect(calls[0].args[0].input.SecretId).toBe(validSecretArn);
    });

    it("should generate new ENCRYPTION_KEY and HMAC_KEY with version", async () => {
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      expect(secrets).toHaveProperty("version", "1");
      expect(secrets).toHaveProperty("ENCRYPTION_KEY");
      expect(secrets).toHaveProperty("HMAC_KEY");
      expect(secrets).toHaveProperty("ROTATED_AT");
    });

    it("should generate base64 encoded 256-bit keys", async () => {
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      // Base64 encoded 32 bytes = 44 characters (with padding)
      expect(secrets.ENCRYPTION_KEY).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(secrets.HMAC_KEY).toMatch(/^[A-Za-z0-9+/]+=*$/);

      // Verify they decode to 32 bytes
      const encKeyBuffer = Buffer.from(secrets.ENCRYPTION_KEY, "base64");
      const hmacKeyBuffer = Buffer.from(secrets.HMAC_KEY, "base64");
      expect(encKeyBuffer.length).toBe(32);
      expect(hmacKeyBuffer.length).toBe(32);
    });

    it("should include ISO timestamp in ROTATED_AT", async () => {
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      await handler();

      const calls = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secretString = calls[0].args[0].input.SecretString;
      const secrets = JSON.parse(secretString!);

      // Verify ROTATED_AT is a valid ISO date string
      const rotatedAt = new Date(secrets.ROTATED_AT);
      expect(rotatedAt.toISOString()).toBe(secrets.ROTATED_AT);
    });

    it("should generate unique keys on each rotation", async () => {
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      // First rotation
      await handler();
      const calls1 = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets1 = JSON.parse(calls1[0].args[0].input.SecretString!);

      // Reset mock for second rotation
      secretsManagerMock.reset();
      secretsManagerMock.on(PutSecretValueCommand).resolves({});

      // Second rotation
      await handler();
      const calls2 = secretsManagerMock.commandCalls(PutSecretValueCommand);
      const secrets2 = JSON.parse(calls2[0].args[0].input.SecretString!);

      // Keys should be different
      expect(secrets1.ENCRYPTION_KEY).not.toBe(secrets2.ENCRYPTION_KEY);
      expect(secrets1.HMAC_KEY).not.toBe(secrets2.HMAC_KEY);
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

    it("should throw error when PutSecretValueCommand fails", async () => {
      const awsError = new Error("Access denied");
      secretsManagerMock.on(PutSecretValueCommand).rejects(awsError);

      await expect(handler()).rejects.toThrow("Access denied");
    });

    it("should propagate AWS errors without modification", async () => {
      const awsError = new Error("ThrottlingException");
      (awsError as any).code = "ThrottlingException";
      secretsManagerMock.on(PutSecretValueCommand).rejects(awsError);

      try {
        await handler();
        expect.fail("Should have thrown");
      } catch (error) {
        expect((error as Error).message).toBe("ThrottlingException");
      }
    });
  });
});
