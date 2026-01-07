// src/services/rotate-aws-secrets.ts
import { SecretsManagerClient, PutSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { randomBytes } from 'crypto';

const client = new SecretsManagerClient({});

/**
 * Rotates encryption and HMAC keys in Secrets Manager
 * Triggered by EventBridge every 48 hours
 */
export const handler = async (): Promise<void> => {
  const secretArn = process.env.SECRET_ARN;

  if (!secretArn) {
    throw new Error('SECRET_ARN environment variable is not set');
  }

  try {
    // Generate new keys
    const newSecrets = {
      ENCRYPTION_KEY: randomBytes(32).toString('base64'), // 256-bit AES key
      HMAC_KEY: randomBytes(32).toString('base64'), // 256-bit HMAC key
      ROTATED_AT: new Date().toISOString(),
    };

    // Update the secret
    await client.send(
      new PutSecretValueCommand({
        SecretId: secretArn,
        SecretString: JSON.stringify(newSecrets),
      }),
    );

    console.log('Secret rotated successfully', { secretArn, rotatedAt: newSecrets.ROTATED_AT });
  } catch (error) {
    console.error('Failed to rotate secret:', error);
    throw error;
  }
};
