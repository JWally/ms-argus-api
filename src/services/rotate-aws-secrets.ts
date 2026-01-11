// src/services/rotate-aws-secrets.ts
import {
  SecretsManagerClient,
  PutSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";
import { randomBytes } from "crypto";

const logger = new Logger({ serviceName: "argus-secrets-rotator" });
const client = new SecretsManagerClient({});

/**
 * Manual secret rotation utility.
 *
 * IMPORTANT: This is NOT automatically invoked (AR-18).
 *
 * Automatic 48-hour rotation was disabled because it destroyed old keys,
 * making historical encrypted data unrecoverable. Use this script for
 * manual rotation during quarterly security reviews or key compromise events.
 *
 * WARNING: Rotating keys will invalidate all encrypted data created with
 * the previous key. Ensure all historical data has been processed or
 * archived before rotation.
 *
 * Future: Implement envelope encryption with KMS for seamless key versioning.
 */
export const handler = async (): Promise<void> => {
  const secretArn = process.env.SECRET_ARN;

  if (!secretArn) {
    throw new Error("SECRET_ARN environment variable is not set");
  }

  try {
    // Generate new keys with version tracking
    const newSecrets = {
      version: "1",
      ENCRYPTION_KEY: randomBytes(32).toString("base64"), // 256-bit AES key
      HMAC_KEY: randomBytes(32).toString("base64"), // 256-bit HMAC key
      ROTATED_AT: new Date().toISOString(),
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
      rotatedAt: newSecrets.ROTATED_AT,
      version: newSecrets.version,
    });
  } catch (error) {
    logger.error("Failed to rotate secret", { error });
    throw error;
  }
};
