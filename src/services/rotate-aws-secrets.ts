// src/services/rotate-aws-secrets.ts
import {
  SecretsManagerClient,
  PutSecretValueCommand,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";
import { randomBytes } from "crypto";
import type { VersionedSecrets } from "./get-aws-secrets";

const logger = new Logger({ serviceName: "argus-secrets-rotator" });
const client = new SecretsManagerClient({});

/**
 * Legacy flat secrets structure
 */
interface LegacySecrets {
  ENCRYPTION_KEY: string;
  HMAC_KEY: string;
  version?: string;
}

/**
 * Manual secret rotation utility with key versioning (AR-28).
 *
 * IMPORTANT: This preserves the previous key during rotation to prevent
 * split-brain issues where some Lambda instances have cached old keys.
 * Data encrypted with the previous key remains readable for one full
 * cache duration (15 minutes) after rotation.
 *
 * The rotation process:
 * 1. Fetch current secret
 * 2. Move current keys to "previous"
 * 3. Generate new keys as "current"
 * 4. Increment version number
 * 5. Update secret with both keys
 */
export const handler = async (): Promise<void> => {
  const secretArn = process.env.SECRET_ARN;

  if (!secretArn) {
    throw new Error("SECRET_ARN environment variable is not set");
  }

  try {
    // Fetch existing secret to preserve current keys as previous
    const getCommand = new GetSecretValueCommand({ SecretId: secretArn });
    const existingData = await client.send(getCommand);
    const existingSecret = JSON.parse(existingData.SecretString!) as
      | VersionedSecrets
      | LegacySecrets;

    // Extract current keys from either versioned or legacy format
    let currentKeys: { ENCRYPTION_KEY: string; HMAC_KEY: string };
    let currentVersion: number;

    if ("current" in existingSecret && existingSecret.current) {
      // Versioned format
      currentKeys = existingSecret.current;
      currentVersion =
        typeof existingSecret.version === "number" ? existingSecret.version : 1;
    } else {
      // Legacy flat format
      const legacy = existingSecret as LegacySecrets;
      currentKeys = {
        ENCRYPTION_KEY: legacy.ENCRYPTION_KEY,
        HMAC_KEY: legacy.HMAC_KEY,
      };
      currentVersion = 1;
    }

    // Generate new versioned secret structure
    const newSecrets: VersionedSecrets & { rotatedAt: string } = {
      version: currentVersion + 1,
      current: {
        ENCRYPTION_KEY: randomBytes(32).toString("base64"), // 256-bit AES key
        HMAC_KEY: randomBytes(32).toString("base64"), // 256-bit HMAC key
      },
      previous: currentKeys, // Preserve current keys as previous
      rotatedAt: new Date().toISOString(),
    };

    // Update the secret
    await client.send(
      new PutSecretValueCommand({
        SecretId: secretArn,
        SecretString: JSON.stringify(newSecrets),
      }),
    );

    logger.info("Secret rotated successfully", {
      secretArn,
      rotatedAt: newSecrets.rotatedAt,
      version: newSecrets.version,
    });
  } catch (error) {
    logger.error("Failed to rotate secret", { error });
    throw error;
  }
};
