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
import { fnv1a } from "../../helpers/hash";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME || "valkey-client",
});

const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
});

// Singleton client instance
let client: Redis | null = null;

/** Global sampling rate for write-side counters. 1.0 = every request, 0.01 = 1%. */
function getGlobalSampleRate(): number {
  return parseFloat(process.env.GLOBAL_SAMPLE_RATE || "0.01");
}

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
 * Global updates are sampled at GLOBAL_SAMPLE_RATE to reduce write load.
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

    // Sample global updates to reduce write load (configurable per stage)
    const sampleRate = getGlobalSampleRate();
    if (Math.random() < sampleRate) {
      const globalTlsKey = `global:${deviceType}:tls:hist`;
      const globalMssKey = `global:${deviceType}:mss:hist`;
      const globalTotalKey = `global:${deviceType}:total`;

      // Compensate for sampling (e.g., 1% sampling → increment by 100)
      const compensation = Math.round(1 / sampleRate);
      pipeline.hincrby(globalTlsKey, tlsRatioBucket, compensation);
      pipeline.hincrby(globalMssKey, mssBucket, compensation);
      pipeline.incrby(globalTotalKey, compensation);
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

function parseBaselineResults(results: [Error | null, unknown][]): {
  asn: NetworkHistograms;
  global: NetworkHistograms;
} {
  const asnTlsRaw = (results[0]?.[1] as Record<string, string>) || {};
  const asnMssRaw = (results[1]?.[1] as Record<string, string>) || {};
  const asnTotal = parseInt((results[2]?.[1] as string) || "0", 10);
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
}

/** Fetch network baseline histograms for both ASN-specific and global. */
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
    if (!redisClient) return emptyResult;

    const startTime = Date.now();
    const prefix = `asn:${asn}:${deviceType}`;
    const globalPrefix = `global:${deviceType}`;

    const pipeline = redisClient.pipeline();
    pipeline.hgetall(`${prefix}:tls:hist`);
    pipeline.hgetall(`${prefix}:mss:hist`);
    pipeline.get(`${prefix}:total`);
    pipeline.hgetall(`${globalPrefix}:tls:hist`);
    pipeline.hgetall(`${globalPrefix}:mss:hist`);
    pipeline.get(`${globalPrefix}:total`);

    const results = await pipeline.exec();
    metrics.addMetric(
      "ValkeyNetworkBaselineReadMs",
      MetricUnit.Milliseconds,
      Date.now() - startTime,
    );

    if (!results || results.length < 6) {
      logger.warn("Unexpected network baseline pipeline results", { results });
      return emptyResult;
    }

    return parseBaselineResults(results as [Error | null, unknown][]);
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

interface V2Keys {
  groupCount: string;
  groupTotal: string;
}

function buildV2Keys(
  groupingKey: string,
  type: string,
  fingerprint: string,
): V2Keys {
  const keyHash = fnv1a(groupingKey);
  return {
    groupCount: `stat:v2:${keyHash}:${type}:${fingerprint}`,
    groupTotal: `stat:v2:${keyHash}:${type}:_total`,
  };
}

async function setV2TTLs(
  redisClient: Redis,
  keys: V2Keys,
  count: number,
): Promise<void> {
  const ttlPipeline = redisClient.pipeline();
  ttlPipeline.expire(keys.groupCount, getTieredTTL(count));
  ttlPipeline.expire(keys.groupTotal, 24 * 3600);
  await ttlPipeline.exec();
}

function parseV2PipelineResults(
  results: [Error | null, unknown][],
): StatisticalV2Data {
  return {
    count: parseInt((results[0]?.[1] as string) || "0", 10) + 1,
    total: parseInt((results[1]?.[1] as string) || "0", 10) + 1,
    globalCount: 0,
    globalTotal: 0,
  };
}

const NEUTRAL_V2_DATA: StatisticalV2Data = {
  count: 1,
  total: 1,
  globalCount: 0,
  globalTotal: 0,
};

/** Record a fingerprint observation and get statistical v2 data. */
export async function recordFingerprintV2(
  groupingKey: string,
  type: string,
  fingerprint: string,
): Promise<StatisticalV2Data> {
  try {
    const redisClient = getClient();
    if (!redisClient) return NEUTRAL_V2_DATA;

    const startTime = Date.now();
    const keys = buildV2Keys(groupingKey, type, fingerprint);
    const pipeline = redisClient.pipeline();
    pipeline.get(keys.groupCount);
    pipeline.get(keys.groupTotal);
    pipeline.incr(keys.groupCount);
    pipeline.incr(keys.groupTotal);

    const results = await pipeline.exec();
    if (!results) {
      logger.warn("Unexpected null Valkey pipeline results");
      return NEUTRAL_V2_DATA;
    }

    const data = parseV2PipelineResults(results as [Error | null, unknown][]);
    await setV2TTLs(redisClient, keys, data.count);
    metrics.addMetric(
      "ValkeyStatisticalV2OperationMs",
      MetricUnit.Milliseconds,
      Date.now() - startTime,
    );
    return data;
  } catch (error) {
    logger.warn("Valkey statistical v2 operation failed", {
      error,
      groupingKey,
      type,
    });
    metrics.addMetric("ValkeyStatisticalV2OperationError", MetricUnit.Count, 1);
    return NEUTRAL_V2_DATA;
  }
}

/**
 * Fetch statistical v2 data without recording.
 *
 * Used during pre-fetch phase to get counts for scoring.
 *
 * @param groupingKey - Composite grouping key (e.g., "Mozilla/5.0...:chrome")
 * @param type - Fingerprint type (e.g., 'ja4', 'h2')
 * @param fingerprint - The fingerprint value
 * @returns Statistical data or null on failure
 */
export async function fetchStatisticalV2Data(
  groupingKey: string,
  type: string,
  fingerprint: string,
): Promise<StatisticalV2Data | null> {
  try {
    const redisClient = getClient();
    if (!redisClient) {
      return null;
    }

    const startTime = Date.now();

    const keys = buildV2Keys(groupingKey, type, fingerprint);

    // Pipeline reads for group counts only
    const pipeline = redisClient.pipeline();
    pipeline.get(keys.groupCount);
    pipeline.get(keys.groupTotal);

    const results = await pipeline.exec();

    const duration = Date.now() - startTime;
    metrics.addMetric(
      "ValkeyStatisticalV2FetchMs",
      MetricUnit.Milliseconds,
      duration,
    );

    if (!results || results.length < 2) {
      return null;
    }

    return {
      count: parseInt((results[0]?.[1] as string) || "0", 10),
      total: parseInt((results[1]?.[1] as string) || "0", 10),
      globalCount: 0,
      globalTotal: 0,
    };
  } catch (error) {
    logger.warn("Valkey statistical v2 fetch failed", {
      error,
      groupingKey,
      type,
    });
    metrics.addMetric("ValkeyStatisticalV2FetchError", MetricUnit.Count, 1);
    return null;
  }
}
