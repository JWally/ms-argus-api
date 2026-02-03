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

// ============================================================================
// Network Baseline Histogram Operations
// ============================================================================

/** Histogram data for a single metric (tls_ratio or mss) */
export interface HistogramData {
  /** Map of bucket_id → count */
  buckets: Map<string, number>;
  /** Total observations */
  total: number;
}

/** Combined histograms for network baseline */
export interface NetworkHistograms {
  tlsRatio: HistogramData;
  mss: HistogramData;
}

/** Empty histogram returned when no data exists */
const EMPTY_HISTOGRAM: HistogramData = {
  buckets: new Map(),
  total: 0,
};

/**
 * Record network metrics to histograms.
 *
 * Updates both ASN-specific and global histograms.
 * Global updates are sampled at 1% to reduce write load.
 *
 * Key schema:
 * - asn:{asn}:{deviceType}:tls:hist → HASH { bucket_id: count }
 * - asn:{asn}:{deviceType}:mss:hist → HASH { bucket_id: count }
 * - asn:{asn}:{deviceType}:total → INT
 * - global:{deviceType}:tls:hist → HASH
 * - global:{deviceType}:mss:hist → HASH
 * - global:{deviceType}:total → INT
 *
 * @param asn - Autonomous System Number
 * @param deviceType - Device type (desktop, mobile, tablet)
 * @param tlsRatioBucket - Bucket ID for tls_ratio
 * @param mssBucket - Bucket ID for mss
 */
export async function recordNetworkMetrics(
  asn: string,
  deviceType: string,
  tlsRatioBucket: string,
  mssBucket: string,
): Promise<void> {
  const ttl = parseInt(process.env.VALKEY_TTL_SECONDS || "172800", 10);

  try {
    const redisClient = getClient();
    if (!redisClient) {
      return;
    }

    const startTime = Date.now();

    // ASN-specific keys
    const asnTlsKey = `asn:${asn}:${deviceType}:tls:hist`;
    const asnMssKey = `asn:${asn}:${deviceType}:mss:hist`;
    const asnTotalKey = `asn:${asn}:${deviceType}:total`;

    // Pipeline for ASN-specific updates
    const pipeline = redisClient.pipeline();
    pipeline.hincrby(asnTlsKey, tlsRatioBucket, 1);
    pipeline.hincrby(asnMssKey, mssBucket, 1);
    pipeline.incr(asnTotalKey);
    pipeline.expire(asnTlsKey, ttl);
    pipeline.expire(asnMssKey, ttl);
    pipeline.expire(asnTotalKey, ttl);

    // Sample global updates at 1% to reduce write load
    if (Math.random() < 0.01) {
      const globalTlsKey = `global:${deviceType}:tls:hist`;
      const globalMssKey = `global:${deviceType}:mss:hist`;
      const globalTotalKey = `global:${deviceType}:total`;

      // Increment by 100 to compensate for 1% sampling
      pipeline.hincrby(globalTlsKey, tlsRatioBucket, 100);
      pipeline.hincrby(globalMssKey, mssBucket, 100);
      pipeline.incrby(globalTotalKey, 100);
      pipeline.expire(globalTlsKey, ttl);
      pipeline.expire(globalMssKey, ttl);
      pipeline.expire(globalTotalKey, ttl);
    }

    await pipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric(
      "ValkeyNetworkBaselineWriteMs",
      MetricUnit.Milliseconds,
      duration,
    );
  } catch (error) {
    logger.warn("Failed to record network metrics", { error, asn, deviceType });
    metrics.addMetric("ValkeyNetworkBaselineWriteError", MetricUnit.Count, 1);
  }
}

/**
 * Fetch network baseline histograms for both ASN-specific and global.
 *
 * Performs a single pipelined read for efficiency.
 *
 * @param asn - Autonomous System Number
 * @param deviceType - Device type (desktop, mobile, tablet)
 * @returns Both ASN-specific and global histograms
 */
export async function getNetworkBaselines(
  asn: string,
  deviceType: string,
): Promise<{ asn: NetworkHistograms; global: NetworkHistograms }> {
  const emptyResult = {
    asn: { tlsRatio: EMPTY_HISTOGRAM, mss: EMPTY_HISTOGRAM },
    global: { tlsRatio: EMPTY_HISTOGRAM, mss: EMPTY_HISTOGRAM },
  };

  try {
    const redisClient = getClient();
    if (!redisClient) {
      return emptyResult;
    }

    const startTime = Date.now();

    // Keys
    const asnTlsKey = `asn:${asn}:${deviceType}:tls:hist`;
    const asnMssKey = `asn:${asn}:${deviceType}:mss:hist`;
    const asnTotalKey = `asn:${asn}:${deviceType}:total`;
    const globalTlsKey = `global:${deviceType}:tls:hist`;
    const globalMssKey = `global:${deviceType}:mss:hist`;
    const globalTotalKey = `global:${deviceType}:total`;

    // Pipeline all reads
    const pipeline = redisClient.pipeline();
    pipeline.hgetall(asnTlsKey);
    pipeline.hgetall(asnMssKey);
    pipeline.get(asnTotalKey);
    pipeline.hgetall(globalTlsKey);
    pipeline.hgetall(globalMssKey);
    pipeline.get(globalTotalKey);

    const results = await pipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric(
      "ValkeyNetworkBaselineReadMs",
      MetricUnit.Milliseconds,
      duration,
    );

    if (!results || results.length < 6) {
      logger.warn("Unexpected network baseline pipeline results", { results });
      return emptyResult;
    }

    // Parse ASN histograms
    const asnTlsRaw = (results[0]?.[1] as Record<string, string>) || {};
    const asnMssRaw = (results[1]?.[1] as Record<string, string>) || {};
    const asnTotal = parseInt((results[2]?.[1] as string) || "0", 10);

    // Parse global histograms
    const globalTlsRaw = (results[3]?.[1] as Record<string, string>) || {};
    const globalMssRaw = (results[4]?.[1] as Record<string, string>) || {};
    const globalTotal = parseInt((results[5]?.[1] as string) || "0", 10);

    return {
      asn: {
        tlsRatio: parseHistogram(asnTlsRaw, asnTotal),
        mss: parseHistogram(asnMssRaw, asnTotal),
      },
      global: {
        tlsRatio: parseHistogram(globalTlsRaw, globalTotal),
        mss: parseHistogram(globalMssRaw, globalTotal),
      },
    };
  } catch (error) {
    logger.warn("Failed to get network baselines", { error, asn, deviceType });
    metrics.addMetric("ValkeyNetworkBaselineReadError", MetricUnit.Count, 1);
    return emptyResult;
  }
}

/**
 * Parse raw Redis hash into histogram data.
 */
function parseHistogram(
  raw: Record<string, string>,
  total: number,
): HistogramData {
  const buckets = new Map<string, number>();
  for (const [key, value] of Object.entries(raw)) {
    buckets.set(key, parseInt(value, 10) || 0);
  }
  return { buckets, total };
}

/**
 * Check if network baseline detection is enabled.
 */
export function isNetworkBaselineEnabled(): boolean {
  return (
    !!process.env.VALKEY_ENDPOINT &&
    process.env.NETWORK_BASELINE_ENABLED === "true"
  );
}

// ============================================================================
// Statistical V2 Operations (Shannon Scoring + Tiered TTLs)
// ============================================================================

/** Statistical v2 data for a single fingerprint type */
export interface StatisticalV2Data {
  /** Count for this fingerprint within the UA family */
  count: number;
  /** Total observations for this UA family */
  total: number;
  /** Count across all UA families (global) */
  globalCount: number;
  /** Total global observations */
  globalTotal: number;
}

/**
 * Get tiered TTL based on observation count.
 *
 * Higher-traffic fingerprints get longer TTLs (they're more stable):
 * - >= 20,000: 90 days (hot tier - well-established)
 * - >= 1,000: 24 hours (warm tier - moderate traffic)
 * - < 1,000: 3 hours (cold tier - low traffic, may be anomalous)
 *
 * @param count - Number of observations for this fingerprint
 * @returns TTL in seconds
 */
export function getTieredTTL(count: number): number {
  if (count >= 20_000) return 90 * 24 * 3600; // 90 days
  if (count >= 1_000) return 24 * 3600; // 24 hours
  return 3 * 3600; // 3 hours
}

/**
 * Check if statistical v2 detection is enabled.
 */
export function isStatisticalV2Enabled(): boolean {
  return (
    !!process.env.VALKEY_ENDPOINT &&
    process.env.STATISTICAL_V2_ENABLED === "true"
  );
}

/**
 * Record a fingerprint observation and get statistical v2 data.
 *
 * Records to both UA-family-specific and global counters.
 * Uses tiered TTLs based on observation count.
 * Global updates are sampled at 1% to reduce write load.
 *
 * Key schema:
 * - stat:v2:{ua_family}:{type}:{fingerprint} → counter (tiered TTL)
 * - stat:v2:{ua_family}:{type}:_total → counter (24h TTL)
 * - stat:v2:_global:{type}:{fingerprint} → counter (1% sampled)
 * - stat:v2:_global:{type}:_total → counter
 *
 * @param uaFamily - Browser family (e.g., "Chrome", "Firefox")
 * @param type - Fingerprint type ('ja4' or 'h2')
 * @param fingerprint - The fingerprint value
 * @returns Statistical data for computing Shannon score
 */
export async function recordFingerprintV2(
  uaFamily: string,
  type: string,
  fingerprint: string,
): Promise<StatisticalV2Data> {
  const neutralData: StatisticalV2Data = {
    count: 1,
    total: 1,
    globalCount: 1,
    globalTotal: 1,
  };

  try {
    const redisClient = getClient();
    if (!redisClient) {
      return neutralData;
    }

    const startTime = Date.now();

    // Key names for UA-specific counters
    const uaCountKey = `stat:v2:${uaFamily}:${type}:${fingerprint}`;
    const uaTotalKey = `stat:v2:${uaFamily}:${type}:_total`;

    // Key names for global counters
    const globalCountKey = `stat:v2:_global:${type}:${fingerprint}`;
    const globalTotalKey = `stat:v2:_global:${type}:_total`;

    // Pipeline for reads + increments
    const pipeline = redisClient.pipeline();

    // Read current counts first (for TTL calculation)
    pipeline.get(uaCountKey);
    pipeline.get(uaTotalKey);
    pipeline.get(globalCountKey);
    pipeline.get(globalTotalKey);

    // Increment UA-specific counters
    pipeline.incr(uaCountKey);
    pipeline.incr(uaTotalKey);

    // Sample global updates at 1% to reduce write load
    const shouldUpdateGlobal = Math.random() < 0.01;
    if (shouldUpdateGlobal) {
      // Increment by 100 to compensate for 1% sampling
      pipeline.incrby(globalCountKey, 100);
      pipeline.incrby(globalTotalKey, 100);
    }

    const results = await pipeline.exec();

    if (!results) {
      logger.warn("Unexpected null Valkey pipeline results");
      return neutralData;
    }

    // Parse read results (indices 0-3)
    const prevCount = parseInt((results[0]?.[1] as string) || "0", 10);
    const prevTotal = parseInt((results[1]?.[1] as string) || "0", 10);
    const globalCount = parseInt((results[2]?.[1] as string) || "0", 10);
    const globalTotal = parseInt((results[3]?.[1] as string) || "0", 10);

    // Current counts after increment
    const count = prevCount + 1;
    const total = prevTotal + 1;

    // Set tiered TTL based on new count
    const ttl = getTieredTTL(count);
    const ttlPipeline = redisClient.pipeline();
    ttlPipeline.expire(uaCountKey, ttl);
    ttlPipeline.expire(uaTotalKey, 24 * 3600); // Total always 24h
    if (shouldUpdateGlobal) {
      ttlPipeline.expire(globalCountKey, 7 * 24 * 3600); // Global: 7 days
      ttlPipeline.expire(globalTotalKey, 7 * 24 * 3600);
    }
    await ttlPipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric(
      "ValkeyStatisticalV2OperationMs",
      MetricUnit.Milliseconds,
      duration,
    );

    return {
      count,
      total,
      // Adjust global counts for 1% sampling
      globalCount: Math.max(1, globalCount),
      globalTotal: Math.max(1, globalTotal),
    };
  } catch (error) {
    logger.warn("Valkey statistical v2 operation failed", {
      error,
      uaFamily,
      type,
    });
    metrics.addMetric("ValkeyStatisticalV2OperationError", MetricUnit.Count, 1);
    return neutralData;
  }
}

/**
 * Fetch statistical v2 data without recording.
 *
 * Used during pre-fetch phase to get counts for scoring.
 *
 * @param uaFamily - Browser family
 * @param type - Fingerprint type (e.g., 'ja4', 'h2')
 * @param fingerprint - The fingerprint value
 * @returns Statistical data or null on failure
 */
export async function fetchStatisticalV2Data(
  uaFamily: string,
  type: string,
  fingerprint: string,
): Promise<StatisticalV2Data | null> {
  try {
    const redisClient = getClient();
    if (!redisClient) {
      return null;
    }

    const startTime = Date.now();

    // Key names
    const uaCountKey = `stat:v2:${uaFamily}:${type}:${fingerprint}`;
    const uaTotalKey = `stat:v2:${uaFamily}:${type}:_total`;
    const globalCountKey = `stat:v2:_global:${type}:${fingerprint}`;
    const globalTotalKey = `stat:v2:_global:${type}:_total`;

    // Pipeline all reads
    const pipeline = redisClient.pipeline();
    pipeline.get(uaCountKey);
    pipeline.get(uaTotalKey);
    pipeline.get(globalCountKey);
    pipeline.get(globalTotalKey);

    const results = await pipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric(
      "ValkeyStatisticalV2FetchMs",
      MetricUnit.Milliseconds,
      duration,
    );

    if (!results || results.length < 4) {
      return null;
    }

    return {
      count: parseInt((results[0]?.[1] as string) || "0", 10),
      total: parseInt((results[1]?.[1] as string) || "0", 10),
      globalCount: parseInt((results[2]?.[1] as string) || "0", 10),
      globalTotal: parseInt((results[3]?.[1] as string) || "0", 10),
    };
  } catch (error) {
    logger.warn("Valkey statistical v2 fetch failed", {
      error,
      uaFamily,
      type,
    });
    metrics.addMetric("ValkeyStatisticalV2FetchError", MetricUnit.Count, 1);
    return null;
  }
}
