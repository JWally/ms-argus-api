// src/services/get-aws-secrets.ts
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";
import {
  AWS_SECRETS_REQUIRED_KEYS,
  KEY_CACHE_DURATION,
  ERROR_STRINGS,
} from "../helpers/constants";

const logger = new Logger({ serviceName: "argus-secrets" });

/**
 * Versioned secrets structure
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

function parseSecretResponse(
  secret: VersionedSecrets | LegacySecrets,
): VersionedSecrets {
  if ("current" in secret && secret.current) {
    return {
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
  }
  const legacy = secret as LegacySecrets;
  const missingKeys = AWS_SECRETS_REQUIRED_KEYS.filter(
    (key) => !legacy[key as keyof LegacySecrets],
  );
  if (missingKeys.length > 0) {
    throw new Error(`Missing required keys: ${missingKeys.join(", ")}`);
  }
  return {
    version: 1,
    current: {
      ENCRYPTION_KEY: legacy.ENCRYPTION_KEY,
      HMAC_KEY: legacy.HMAC_KEY,
    },
  };
}

/**
 * Retrieves versioned secrets from AWS Secrets Manager with caching.
 * Supports both current and previous keys for seamless key rotation.
 */
export const getVersionedSecrets = async (): Promise<VersionedSecrets> => {
  const secretKeyArn = process.env.SECRET_KEY_ARN;
  if (!secretKeyArn) {
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
    const command = new GetSecretValueCommand({ SecretId: secretKeyArn });
    const data = await client.send(command);
    const secret = JSON.parse(data.SecretString!) as
      | VersionedSecrets
      | LegacySecrets;
    cachedSecrets = parseSecretResponse(secret);
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
