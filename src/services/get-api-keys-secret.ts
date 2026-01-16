// src/services/get-api-keys-secret.ts
// AR-131: Fetch API_KEYS from Secrets Manager instead of env var
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Logger } from "@aws-lambda-powertools/logger";
import {
  API_KEYS_SECRET_ARN,
  API_KEYS_CACHE_TTL,
  ERROR_STRINGS,
} from "../helpers/constants";

const logger = new Logger({ serviceName: "argus-api-keys" });

/**
 * API Keys mapping structure: API key -> Tenant ID
 * Example: { "sk_live_abc123": "tenant-1", "sk_live_def456": "tenant-2" }
 */
export type ApiKeysMap = Record<string, string>;

let client: SecretsManagerClient | null = null;
let cachedApiKeys: ApiKeysMap | null = null;
let cacheTimestamp = 0;
let initPromise: Promise<ApiKeysMap> | null = null;
let initCompleted = false;

/**
 * Fetches API keys from Secrets Manager at Lambda init.
 * MUST be called during module initialization - throws if secret unavailable (fail closed).
 * Returns cached keys on subsequent calls.
 */
export const initApiKeysSecret = async (): Promise<ApiKeysMap> => {
  // If already initialized, return cached keys
  if (initCompleted && cachedApiKeys) {
    return cachedApiKeys;
  }

  // If initialization is in progress, wait for it
  if (initPromise) {
    return initPromise;
  }

  // Start initialization
  initPromise = fetchApiKeysFromSecrets(true);

  try {
    const keys = await initPromise;
    initCompleted = true;
    return keys;
  } catch (error) {
    initPromise = null;
    throw error;
  }
};

/**
 * Gets API keys, refreshing cache if expired.
 * Uses graceful degradation: if refresh fails after init, returns stale cache.
 */
export const getApiKeysSecret = async (): Promise<ApiKeysMap> => {
  // If no ARN configured, return empty map (allows header-based tenant ID)
  if (!API_KEYS_SECRET_ARN) {
    return {};
  }

  const isCacheValid =
    cachedApiKeys && Date.now() - cacheTimestamp < API_KEYS_CACHE_TTL;

  if (isCacheValid) {
    return cachedApiKeys!;
  }

  // Cache expired - attempt refresh
  try {
    return await fetchApiKeysFromSecrets(false);
  } catch (error) {
    // Graceful degradation: if we have stale cache, use it
    if (cachedApiKeys) {
      logger.warn("Failed to refresh API keys, using stale cache", { error });
      return cachedApiKeys;
    }
    // No cache available - this shouldn't happen after successful init
    throw error;
  }
};

/**
 * Internal function to fetch API keys from Secrets Manager.
 * @param failOnError - If true, throws on error (for init). If false, allows graceful degradation.
 */
const fetchApiKeysFromSecrets = async (
  failOnError: boolean,
): Promise<ApiKeysMap> => {
  if (!API_KEYS_SECRET_ARN) {
    if (failOnError) {
      throw new Error(ERROR_STRINGS.API_KEYS_ARN_NOT_SET);
    }
    return {};
  }

  if (!client) {
    client = new SecretsManagerClient({});
  }

  try {
    const command = new GetSecretValueCommand({
      SecretId: API_KEYS_SECRET_ARN,
    });
    const data = await client.send(command);

    if (!data.SecretString) {
      throw new Error("Secret value is empty");
    }

    const parsed = JSON.parse(data.SecretString) as ApiKeysMap;

    // Validate structure: should be a flat object of string -> string
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new Error("Invalid API keys format: expected object");
    }

    for (const [key, value] of Object.entries(parsed)) {
      if (typeof key !== "string" || typeof value !== "string") {
        throw new Error(
          "Invalid API keys format: all entries must be string -> string",
        );
      }
    }

    cachedApiKeys = parsed;
    cacheTimestamp = Date.now();
    return cachedApiKeys;
  } catch (error) {
    logger.error("Error retrieving API keys secret", { error });
    if (failOnError) {
      throw new Error(ERROR_STRINGS.API_KEYS_FETCH_FAILED);
    }
    throw error;
  }
};

/**
 * Clears the cache - used for testing only.
 */
export const clearApiKeysCache = (): void => {
  cachedApiKeys = null;
  cacheTimestamp = 0;
  initPromise = null;
  initCompleted = false;
};

/**
 * Resets the client - used for testing only.
 */
export const resetClient = (): void => {
  client = null;
};
