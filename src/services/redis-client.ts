// src/services/redis-client.ts
// AR-48: Shared Redis client for Lambda handlers
// Extracted from matching-worker.ts and profile-updater.ts to reduce duplication

import Redis from "ioredis";
import { REDIS_RETRY_BASE_MS, REDIS_RETRY_MAX_MS } from "../helpers/constants";

/**
 * Configuration for Redis client
 */
export interface RedisClientConfig {
  endpoint: string;
  port: number;
}

// Singleton Redis client (reused across Lambda invocations)
let redisClient: Redis | null = null;
let currentConfig: RedisClientConfig | null = null;

/**
 * Get or create a Redis client with Lambda-optimized settings
 *
 * The client is a singleton that persists across Lambda invocations.
 * Settings are optimized for Lambda's execution model:
 * - Short timeouts to fail fast
 * - Limited retries (Lambda has limited execution time)
 * - Keep-alive for connection reuse
 * - TLS enabled for ElastiCache
 *
 * @param config Redis connection configuration
 * @returns Redis client instance
 */
export function getRedisClient(config: RedisClientConfig): Redis {
  // If client exists and config hasn't changed, return existing client
  if (
    redisClient &&
    currentConfig?.endpoint === config.endpoint &&
    currentConfig?.port === config.port
  ) {
    return redisClient;
  }

  // Create new client (or replace if config changed)
  redisClient = new Redis({
    host: config.endpoint,
    port: config.port,
    tls: {},
    // Lambda-optimized connection settings (AR-20)
    enableReadyCheck: false, // Skip PING on connect (saves ~10ms)
    maxRetriesPerRequest: 2, // Limited retries - Lambda has limited time
    connectTimeout: 5000, // 5s connect timeout
    commandTimeout: 3000, // 3s command timeout
    keepAlive: 30000, // Keep connections alive for Lambda reuse
    retryStrategy: (times: number) => {
      if (times > 3) return null; // Stop retrying after 3 attempts
      return Math.min(
        Math.pow(2, times) * REDIS_RETRY_BASE_MS,
        REDIS_RETRY_MAX_MS,
      );
    },
  });

  currentConfig = config;
  return redisClient;
}

/**
 * Get Redis client using environment variables
 *
 * Convenience function that reads REDIS_ENDPOINT and REDIS_PORT from
 * process.env, eliminating the need for duplicate getRedis() wrappers
 * in each Lambda handler.
 *
 * @returns Redis client instance
 * @throws Error if REDIS_ENDPOINT is not set
 */
export function getRedis(): Redis {
  const endpoint = process.env.REDIS_ENDPOINT;
  const port = parseInt(process.env.REDIS_PORT || "6379", 10);

  if (!endpoint) {
    throw new Error("REDIS_ENDPOINT environment variable is required");
  }

  return getRedisClient({ endpoint, port });
}

/**
 * Close the Redis connection (for testing/cleanup)
 */
export function closeRedisClient(): void {
  if (redisClient) {
    redisClient.disconnect();
    redisClient = null;
    currentConfig = null;
  }
}
