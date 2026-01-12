// src/services/get-aws-secrets.ts
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";
import {
  AWS_SECRETS_REQUIRED_KEYS,
  KEY_CACHE_DURATION,
  SECRET_KEY_ARN,
  ERROR_STRINGS,
} from "../helpers/constants";

const logger = new Logger({ serviceName: "argus-secrets" });

/**
 * Versioned secrets structure (AR-28)
 * Supports key rotation without split-brain issues
 */
export interface VersionedSecrets {
  version: number;
  current: {
    ENCRYPTION_KEY: string;
    HMAC_KEY: string;
  };
  previous?: {
    ENCRYPTION_KEY: string;
    HMAC_KEY: string;
  };
}

/**
 * Legacy flat secrets structure (for backwards compatibility)
 */
interface LegacySecrets {
  ENCRYPTION_KEY: string;
  HMAC_KEY: string;
  version?: string;
}

let client: SecretsManagerClient | null = null;
let cachedSecrets: VersionedSecrets | null = null;
let cacheTimestamp = 0;

/**
 * Retrieves versioned secrets from AWS Secrets Manager with caching.
 * Supports both current and previous keys for seamless key rotation (AR-28).
 */
export const getVersionedSecrets = async (): Promise<VersionedSecrets> => {
  if (!SECRET_KEY_ARN) {
    throw new Error(ERROR_STRINGS.KEY_ARN_NOT_SET);
  }

  if (!client) {
    client = new SecretsManagerClient({});
  }

  const isCacheValid =
    cachedSecrets && Date.now() - cacheTimestamp < KEY_CACHE_DURATION;

  if (isCacheValid) {
    return cachedSecrets!;
  }

  try {
    const command = new GetSecretValueCommand({ SecretId: SECRET_KEY_ARN });
    const data = await client.send(command);
    const secret = JSON.parse(data.SecretString!) as
      | VersionedSecrets
      | LegacySecrets;

    // Handle versioned format (new structure)
    if ("current" in secret && secret.current) {
      cachedSecrets = {
        version: typeof secret.version === "number" ? secret.version : 1,
        current: {
          ENCRYPTION_KEY: secret.current.ENCRYPTION_KEY,
          HMAC_KEY: secret.current.HMAC_KEY,
        },
        previous: secret.previous
          ? {
              ENCRYPTION_KEY: secret.previous.ENCRYPTION_KEY,
              HMAC_KEY: secret.previous.HMAC_KEY,
            }
          : undefined,
      };
    } else {
      // Handle legacy flat format (backwards compatibility)
      const legacySecret = secret as LegacySecrets;
      const missingKeys = AWS_SECRETS_REQUIRED_KEYS.filter(
        (key) => !legacySecret[key as keyof LegacySecrets],
      );
      if (missingKeys.length > 0) {
        throw new Error(`Missing required keys: ${missingKeys.join(", ")}`);
      }

      cachedSecrets = {
        version: 1,
        current: {
          ENCRYPTION_KEY: legacySecret.ENCRYPTION_KEY,
          HMAC_KEY: legacySecret.HMAC_KEY,
        },
      };
    }

    cacheTimestamp = Date.now();
    return cachedSecrets;
  } catch (error) {
    logger.error("Error retrieving secret", { error });
    throw new Error(ERROR_STRINGS.SECRETS_MANAGER_FAILED);
  }
};

/**
 * Legacy function for backwards compatibility.
 * Returns only the current keys in flat format.
 */
export const getAwsSecrets = async (): Promise<Record<string, string>> => {
  const versioned = await getVersionedSecrets();
  return {
    ENCRYPTION_KEY: versioned.current.ENCRYPTION_KEY,
    HMAC_KEY: versioned.current.HMAC_KEY,
  };
};

export const clearCache = (): void => {
  cachedSecrets = null;
  cacheTimestamp = 0;
};
