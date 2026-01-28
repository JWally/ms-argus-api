/**
 * Valkey (Redis-compatible) client for statistical anomaly detection.
 *
 * Tracks ua_family::ja4 combo frequencies using:
 * - Atomic counters for total and combo counts
 * - HyperLogLog for distinct value cardinality estimation
 *
 * Key schema:
 * - ua:{ua_family}:total - Total requests for UA family
 * - ua:{ua_family}:ja4:{ja4} - Requests for specific UA+JA4 combo
 * - ua:{ua_family}:distinct - HyperLogLog of distinct JA4 values
 *
 * @module services/cache/valkey-client
 */

import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import Redis from "ioredis";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "valkey-client",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

/** Statistical data returned from Valkey */
export interface StatisticalData {
  /** Total requests for this UA family */
  total: number;
  /** Requests for this specific UA+JA4 combo */
  comboCount: number;
  /** Estimated distinct JA4 values seen for this UA family */
  distinct: number;
}

/** Neutral stats returned on failure (won't trigger false positives) */
const NEUTRAL_STATS: StatisticalData = {
  total: 1,
  comboCount: 1,
  distinct: 1,
};

// Singleton client instance
let client: Redis | null = null;

/**
 * Get or create the singleton Valkey client.
 *
 * Uses ioredis with automatic reconnection.
 * Returns null if VALKEY_ENDPOINT is not configured.
 */
function getClient(): Redis | null {
  const endpoint = process.env.VALKEY_ENDPOINT;
  if (!endpoint) {
    return null;
  }

  // Return existing client (ioredis handles reconnection automatically)
  if (client) {
    return client;
  }

  // Create new connection
  // ElastiCache Serverless requires TLS on port 6379
  client = new Redis({
    host: endpoint,
    port: 6379,
    tls: {}, // Enable TLS for ElastiCache Serverless
    connectTimeout: 5000,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => {
      // Exponential backoff: 100ms, 200ms, 400ms, ... max 3s
      if (times > 10) {
        logger.error("Valkey connection retries exhausted", { retries: times });
        return null; // Stop retrying
      }
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true, // Don't connect until first command
  });

  client.on("error", (err: Error) => {
    logger.warn("Valkey client error", { error: String(err) });
    metrics.addMetric("ValkeyConnectionError", MetricUnit.Count, 1);
  });

  client.on("reconnecting", () => {
    logger.info("Valkey client reconnecting");
  });

  client.on("connect", () => {
    logger.info("Valkey client connected", { endpoint });
  });

  return client;
}

/**
 * Record a fingerprint observation and get statistical data.
 *
 * Atomically increments counters and updates HyperLogLog in a single pipeline.
 * All keys expire after TTL (default 48h) to bound memory usage.
 *
 * @param uaFamily - Browser family (e.g., "Chrome", "Firefox")
 * @param ja4 - JA4 TLS fingerprint
 * @returns Statistical data for this combination, or neutral stats on failure
 *
 * @example
 * ```typescript
 * const stats = await recordAndGetStats("Chrome", "t13d1516h2_8daaf6152771_b0da82dd1658");
 * // stats = { total: 1000, comboCount: 5, distinct: 200 }
 * // score = 5 / (1000 / 200) = 1.0 (normal)
 *
 * const suspiciousStats = await recordAndGetStats("Chrome", "t13d1516h2_rare_fingerprint");
 * // suspiciousStats = { total: 1000, comboCount: 1, distinct: 200 }
 * // score = 1 / (1000 / 200) = 0.2% (suspicious if < 1%)
 * ```
 */
export async function recordAndGetStats(
  uaFamily: string,
  ja4: string,
): Promise<StatisticalData> {
  const ttl = parseInt(process.env.VALKEY_TTL_SECONDS || "172800", 10); // 48h default

  try {
    const redisClient = getClient();
    if (!redisClient) {
      // Valkey not configured - return neutral stats
      return NEUTRAL_STATS;
    }

    const startTime = Date.now();

    // Key names
    const totalKey = `ua:${uaFamily}:total`;
    const comboKey = `ua:${uaFamily}:ja4:${ja4}`;
    const distinctKey = `ua:${uaFamily}:distinct`;

    // Execute pipeline: INCR total, INCR combo, PFADD distinct, EXPIRE all, PFCOUNT
    // Pipeline reduces round-trips
    const pipeline = redisClient.pipeline();
    pipeline.incr(totalKey);
    pipeline.incr(comboKey);
    pipeline.pfadd(distinctKey, ja4);
    pipeline.expire(totalKey, ttl);
    pipeline.expire(comboKey, ttl);
    pipeline.expire(distinctKey, ttl);
    pipeline.pfcount(distinctKey);

    const results = await pipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric("ValkeyOperationMs", MetricUnit.Milliseconds, duration);

    // Parse pipeline results
    // ioredis returns [[err, result], [err, result], ...]
    if (!results || results.length < 7) {
      logger.warn("Unexpected Valkey pipeline results", { results });
      return NEUTRAL_STATS;
    }

    // Extract values (index 1 of each result tuple)
    const total = results[0]?.[1] as number;
    const comboCount = results[1]?.[1] as number;
    const distinct = results[6]?.[1] as number;

    return {
      total: total || 1,
      comboCount: comboCount || 1,
      distinct: distinct || 1,
    };
  } catch (error) {
    // Log but don't throw - return neutral stats to avoid false positives
    logger.warn("Valkey operation failed", { error, uaFamily, ja4 });
    metrics.addMetric("ValkeyOperationError", MetricUnit.Count, 1);
    return NEUTRAL_STATS;
  }
}

/**
 * Check if Valkey is enabled and configured.
 *
 * @returns true if VALKEY_ENDPOINT is set and statistical detection is enabled
 */
export function isValkeyEnabled(): boolean {
  return (
    !!process.env.VALKEY_ENDPOINT &&
    process.env.STATISTICAL_DETECTION_ENABLED === "true"
  );
}

/**
 * Gracefully close the Valkey connection.
 *
 * Should be called during Lambda shutdown if needed.
 */
export async function closeClient(): Promise<void> {
  if (client) {
    try {
      await client.quit();
      logger.info("Valkey client closed");
    } catch (error) {
      logger.warn("Error closing Valkey client", { error });
    } finally {
      client = null;
    }
  }
}
