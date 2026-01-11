// src/services/matching/matching-service.ts
import { randomUUID } from "crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  QueryCommandOutput,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import type { Redis } from "ioredis";
import {
  Fingerprint,
  FingerprintPayload,
  MatchResult,
  SessionCacheValue,
} from "./types";
import {
  FNV1A_OFFSET_BASIS,
  FNV1A_PRIME,
  TIER2_BUCKET_LIMIT,
} from "../../helpers/constants";

/**
 * Configuration for the matching service
 */
export interface MatchingServiceConfig {
  tier1IndexTable: string;
  tier2BucketsTable: string;
  profilesTable: string;
  profileQueueUrl: string;
  sessionTtlSeconds: number;
  tier2TimeoutMs: number;
}

/**
 * Dependencies injected into the matching service
 */
export interface MatchingServiceDeps {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  redis: Redis;
  config: MatchingServiceConfig;
}

/**
 * Matching service handles device fingerprint matching logic
 * Uses tiered matching strategy:
 * - Tier 0: Redis session cache hit
 * - Tier 0.5: Evercookie/cookie lookup
 * - Tier 1: Strong hash match (stable_hash, fuzzy_hash)
 * - Tier 2: Compound filter match (ip+ja4, gpu+screen+tz, etc)
 * - New Device: Create new device_id
 */
export class MatchingService {
  constructor(private deps: MatchingServiceDeps) {}

  /**
   * Check if session is already cached in Redis
   */
  async checkCache(sessionId: string): Promise<SessionCacheValue | null> {
    const key = `session:${sessionId}`;
    const cached = await this.deps.redis.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  /**
   * Run tiered matching strategy
   * Returns match result along with metadata about the matching process
   */
  async runTieredMatching(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult; tier2TimedOut: boolean }> {
    // Tier 0.5: Evercookie/Cookie lookup
    if (fingerprint.evercookie_id) {
      const result = await this.tier05CookieLookup(
        tenantId,
        fingerprint.evercookie_id,
      );
      if (result) return { result, tier2TimedOut: false };
    }

    // Tier 1: Strong hash match
    const tier1Result = await this.tier1HashMatch(tenantId, fingerprint);
    if (tier1Result) return { result: tier1Result, tier2TimedOut: false };

    // Tier 2: Compound filter match (with timeout)
    const { result: tier2Result, timedOut } =
      await this.tier2CompoundMatchWithTimeout(tenantId, fingerprint);
    if (tier2Result) return { result: tier2Result, tier2TimedOut: timedOut };

    // Tier 3: Vector similarity (TODO: implement when Qdrant is deployed)

    // New device - no match found
    return { result: this.createNewDevice(), tier2TimedOut: timedOut };
  }

  /**
   * Tier 0.5: Lookup by evercookie ID
   * Highest confidence - evercookie is hard to clear
   */
  async tier05CookieLookup(
    tenantId: string,
    evercookieId: string,
  ): Promise<MatchResult | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.tier1IndexTable,
        Key: {
          tenant_id: { S: tenantId },
          hash_key: { S: `evercookie#${evercookieId}` },
        },
      }),
    );

    if (result.Item) {
      const item = unmarshall(result.Item);
      return {
        device_id: item.device_id,
        confidence: 0.99,
        match_tier: 0.5,
        is_new_device: false,
        risk_score: item.risk_score ?? 0.3,
        flags: item.flags ?? [],
      };
    }
    return null;
  }

  /**
   * Tier 1: Match by stable or fuzzy hash
   * High confidence - these hashes are computed from multiple signals
   */
  async tier1HashMatch(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<MatchResult | null> {
    // Try stable hash first (higher confidence)
    if (fingerprint.stable_hash) {
      const result = await this.lookupTier1Index(
        tenantId,
        `stable#${fingerprint.stable_hash}`,
      );
      if (result) {
        return {
          device_id: result.device_id,
          confidence: 0.95,
          match_tier: 1,
          is_new_device: false,
          risk_score: result.risk_score ?? 0.3,
          flags: result.flags ?? [],
        };
      }
    }

    // Try fuzzy hash (slightly lower confidence)
    if (fingerprint.fuzzy_hash) {
      const result = await this.lookupTier1Index(
        tenantId,
        `fuzzy#${fingerprint.fuzzy_hash}`,
      );
      if (result) {
        return {
          device_id: result.device_id,
          confidence: 0.85,
          match_tier: 1,
          is_new_device: false,
          risk_score: result.risk_score ?? 0.3,
          flags: result.flags ?? [],
        };
      }
    }

    return null;
  }

  /**
   * Lookup a single entry in the Tier 1 index
   */
  private async lookupTier1Index(
    tenantId: string,
    hashKey: string,
  ): Promise<{
    device_id: string;
    risk_score?: number;
    flags?: string[];
  } | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.tier1IndexTable,
        Key: {
          tenant_id: { S: tenantId },
          hash_key: { S: hashKey },
        },
      }),
    );

    if (result.Item) {
      const item = unmarshall(result.Item);
      return {
        device_id: item.device_id,
        risk_score: item.risk_score,
        flags: item.flags,
      };
    }
    return null;
  }

  /**
   * Tier 2: Compound filter match with timeout protection
   * Returns result with timedOut flag to track "fail open" scenarios
   */
  async tier2CompoundMatchWithTimeout(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult | null; timedOut: boolean }> {
    const timeoutMs = this.deps.config.tier2TimeoutMs;

    // Use a sentinel to distinguish timeout from null result
    const TIMEOUT_SENTINEL = Symbol("timeout");

    const raceResult = await Promise.race([
      this.tier2CompoundMatch(tenantId, fingerprint).then((r) => ({
        value: r,
        timedOut: false,
      })),
      new Promise<{ value: typeof TIMEOUT_SENTINEL; timedOut: true }>(
        (resolve) =>
          setTimeout(
            () => resolve({ value: TIMEOUT_SENTINEL, timedOut: true }),
            timeoutMs,
          ),
      ),
    ]);

    if (raceResult.timedOut) {
      return { result: null, timedOut: true };
    }

    return { result: raceResult.value as MatchResult | null, timedOut: false };
  }

  /**
   * Tier 2: Match by compound signal buckets
   * Lower confidence - relies on multiple weak signals
   * Uses Query with adjacency list pattern (bucket_key, device_id)
   */
  async tier2CompoundMatch(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<MatchResult | null> {
    const bucketKeys = this.buildBucketKeys(tenantId, fingerprint);
    if (bucketKeys.length === 0) return null;

    // Query all buckets in parallel using adjacency list pattern
    const queries = bucketKeys.map((key) =>
      this.deps.dynamodb.send(
        new QueryCommand({
          TableName: this.deps.config.tier2BucketsTable,
          KeyConditionExpression: "bucket_key = :bk",
          ExpressionAttributeValues: {
            ":bk": { S: key },
          },
          ProjectionExpression: "device_id",
          Limit: TIER2_BUCKET_LIMIT,
        }),
      ),
    );

    const results = await Promise.all(queries);
    const candidates = this.scoreDeviceCandidates(results);

    // Find best match (highest bucket overlap)
    let bestDeviceId: string | null = null;
    let bestScore = 0;

    for (const [deviceId, score] of candidates) {
      if (score > bestScore) {
        bestScore = score;
        bestDeviceId = deviceId;
      }
    }

    // Require at least 2 bucket matches for confidence
    if (bestDeviceId && bestScore >= 2) {
      const profile = await this.loadProfile(tenantId, bestDeviceId);
      return {
        device_id: bestDeviceId,
        confidence: Math.min(0.6 + bestScore * 0.1, 0.85),
        match_tier: 2,
        is_new_device: false,
        risk_score: profile?.risk_score ?? 0.4,
        flags: profile?.flags ?? [],
      };
    }

    return null;
  }

  /**
   * Build compound bucket keys for Tier 2 matching
   */
  buildBucketKeys(tenantId: string, fingerprint: Fingerprint): string[] {
    const keys: string[] = [];

    // IP + JA4 (network identity)
    if (fingerprint.ip_address && fingerprint.ja4) {
      keys.push(
        `${tenantId}#ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`,
      );
    }

    // GPU + Screen + Timezone (hardware/locale identity)
    if (
      fingerprint.gpu_renderer &&
      fingerprint.screen_dims &&
      fingerprint.timezone
    ) {
      keys.push(
        `${tenantId}#gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`,
      );
    }

    // Audio + Canvas (rendering identity)
    if (fingerprint.audio_hash && fingerprint.canvas_hash) {
      keys.push(
        `${tenantId}#audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`,
      );
    }

    return keys;
  }

  /**
   * Score device candidates by counting bucket matches
   * Works with Query results from adjacency list pattern
   */
  private scoreDeviceCandidates(
    results: QueryCommandOutput[],
  ): Map<string, number> {
    const candidates = new Map<string, number>();

    for (const result of results) {
      if (result.Items && result.Items.length > 0) {
        for (const item of result.Items) {
          const unmarshalled = unmarshall(item);
          const deviceId = unmarshalled.device_id;
          if (deviceId) {
            candidates.set(deviceId, (candidates.get(deviceId) ?? 0) + 1);
          }
        }
      }
    }

    return candidates;
  }

  /**
   * Load device profile from DynamoDB
   */
  async loadProfile(
    tenantId: string,
    deviceId: string,
  ): Promise<{ risk_score: number; flags: string[] } | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.profilesTable,
        Key: {
          tenant_id: { S: tenantId },
          device_id: { S: deviceId },
        },
        ProjectionExpression: "risk_score, flags",
      }),
    );

    if (result.Item) {
      const item = unmarshall(result.Item);
      return {
        risk_score: item.risk_score,
        flags: item.flags ?? [],
      };
    }
    return null;
  }

  /**
   * Create a new device when no match is found
   */
  createNewDevice(): MatchResult {
    const deviceId = `dev_${generateUUID()}`;
    return {
      device_id: deviceId,
      confidence: 1.0,
      match_tier: -1,
      is_new_device: true,
      risk_score: 0.5, // Neutral for new devices
      flags: [],
    };
  }

  /**
   * Write match result to Redis session cache
   */
  async writeMatchResult(
    sessionId: string,
    result: MatchResult,
    idempotencyKey: string,
  ): Promise<void> {
    const key = `session:${sessionId}`;

    const value: SessionCacheValue = {
      status: "complete",
      device_id: result.device_id,
      risk_score: result.risk_score,
      confidence: result.confidence,
      match_tier: result.match_tier,
      match_version: Date.now(),
      idempotency_key: idempotencyKey,
      flags: result.flags,
      updated_at: Date.now(),
    };

    // Check if existing result has higher confidence (versioned write)
    const existing = await this.deps.redis.get(key);
    if (existing) {
      const existingValue: SessionCacheValue = JSON.parse(existing);
      if (
        existingValue.confidence >= result.confidence &&
        existingValue.status === "complete"
      ) {
        // Existing match is better, skip write
        return;
      }
    }

    await this.deps.redis.setex(
      key,
      this.deps.config.sessionTtlSeconds,
      JSON.stringify(value),
    );
  }

  /**
   * Write degraded status to Redis when matching fails
   */
  async writeDegradedResult(
    sessionId: string,
    idempotencyKey: string,
  ): Promise<void> {
    const key = `session:${sessionId}`;

    const value: SessionCacheValue = {
      status: "degraded",
      device_id: "",
      risk_score: 0.5,
      confidence: 0,
      match_tier: -1,
      match_version: Date.now(),
      idempotency_key: idempotencyKey,
      flags: ["matching_failed"],
      updated_at: Date.now(),
    };

    await this.deps.redis.setex(
      key,
      this.deps.config.sessionTtlSeconds,
      JSON.stringify(value),
    );
  }

  /**
   * Queue profile update to SQS for async processing
   */
  async queueProfileUpdate(
    tenantId: string,
    deviceId: string,
    payload: FingerprintPayload,
    isNewDevice: boolean = false,
  ): Promise<void> {
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.config.profileQueueUrl,
        MessageBody: JSON.stringify({
          tenant_id: tenantId,
          device_id: deviceId,
          fingerprint: payload.fingerprint,
          tcp_blob: payload.tcp_blob,
          tls_blob: payload.tls_blob,
          timestamp: payload.timestamp,
          is_new_device: isNewDevice,
        }),
      }),
    );
  }
}

/**
 * Generate FNV-1a hash for idempotency key
 * Uses standard 32-bit FNV-1a algorithm
 */
export function generateIdempotencyKey(
  sessionId: string,
  fingerprint: Fingerprint,
): string {
  const input = `${sessionId}:${fingerprint.stable_hash ?? ""}:${fingerprint.canvas_hash ?? ""}`;
  let hash = FNV1A_OFFSET_BASIS;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, FNV1A_PRIME);
  }
  return (hash >>> 0).toString(16);
}

/**
 * Generate a cryptographically secure UUID v4
 * Uses Node.js crypto module for secure random generation
 */
export function generateUUID(): string {
  return randomUUID();
}
