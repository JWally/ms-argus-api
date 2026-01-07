// src/services/get-aws-secrets.ts
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
  AWS_SECRETS_REQUIRED_KEYS,
  KEY_CACHE_DURATION,
  SECRET_KEY_ARN,
  ERROR_STRINGS,
} from '../helpers/constants';

let client: SecretsManagerClient | null = null;
let cachedSecrets: Record<string, string> | null = null;
let cacheTimestamp = 0;

/**
 * Retrieves secrets from AWS Secrets Manager with caching.
 * Returns encryption and HMAC keys for TCP blob decryption.
 */
export const getAwsSecrets = async (): Promise<Record<string, string>> => {
  if (!SECRET_KEY_ARN) {
    throw new Error(ERROR_STRINGS.KEY_ARN_NOT_SET);
  }

  if (!client) {
    client = new SecretsManagerClient({});
  }

  const isCacheValid = cachedSecrets && Date.now() - cacheTimestamp < KEY_CACHE_DURATION;

  if (isCacheValid) {
    return cachedSecrets!;
  }

  try {
    const command = new GetSecretValueCommand({ SecretId: SECRET_KEY_ARN });
    const data = await client.send(command);
    const secret = JSON.parse(data.SecretString!) as Record<string, string>;

    const missingKeys = AWS_SECRETS_REQUIRED_KEYS.filter((key) => !secret[key]);
    if (missingKeys.length > 0) {
      throw new Error(`Missing required keys: ${missingKeys.join(', ')}`);
    }

    cachedSecrets = {
      ENCRYPTION_KEY: secret.ENCRYPTION_KEY,
      HMAC_KEY: secret.HMAC_KEY,
    };

    cacheTimestamp = Date.now();
    return cachedSecrets;
  } catch (error) {
    console.error('Error retrieving secret:', error);
    throw new Error(ERROR_STRINGS.SECRETS_MANAGER_FAILED);
  }
};

export const clearCache = (): void => {
  cachedSecrets = null;
  cacheTimestamp = 0;
};
