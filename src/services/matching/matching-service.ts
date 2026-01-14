// src/services/matching/matching-service.ts
import { randomUUID } from "crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  QueryCommandOutput,
  BatchGetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { DynamoCacheService } from "../cache";
import {
  EvidenceCode,
  Fingerprint,
  FingerprintPayload,
  MatchResult,
  SessionCacheValue,
} from "./types";
import {
  TIER2_BUCKET_LIMIT,
  TIER2_HIGH_CARDINALITY_THRESHOLD,
  TIER2_CARDINALITY_PENALTY,
  TIER2_STATS_SK,
} from "../../helpers/constants";
import { fnv1a } from "../../helpers/hash";

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
  cache: DynamoCacheService; // AR-52: DynamoDB cache replaces Redis
  config: MatchingServiceConfig;
}

/**
 * Matching service handles device fingerprint matching logic
 * Uses tiered matching strategy:
 * - Tier 0: DynamoDB session cache hit (AR-52: was Redis)
 * - Tier 0.5: Evercookie/cookie lookup
 * - Tier 1: Strong hash match (stable_hash, fuzzy_hash)
 * - Tier 2: Compound filter match (ip+ja4, gpu+screen+tz, etc)
 * - New Device: Create new device_id
 */
export class MatchingService {
  constructor(private deps: MatchingServiceDeps) {}

  /**
   * Check if session is already cached (AR-52: DynamoDB replaces Redis)
   */
  async checkCache(sessionId: string): Promise<SessionCacheValue | null> {
    return this.deps.cache.checkSessionCache(sessionId);
  }

  /**
   * Run tiered matching strategy
   * Returns match result along with metadata about the matching process
   */
  async runTieredMatching(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<{
    result: MatchResult;
    tier2TimedOut: boolean;
  }> {
    // Tier 0.5: Cryptographic identity lookup (highest confidence)
    // AR-64: Public key match - ECDSA P-256 key stored in IndexedDB, non-extractable
    if (fingerprint.public_key) {
      const result = await this.tier05PublicKeyLookup(
        tenantId,
        fingerprint.public_key,
      );
      if (result) {
        return {
          result,
          tier2TimedOut: false,
        };
      }
    }

    // Tier 0.5: Evercookie/Cookie lookup
    if (fingerprint.evercookie_id) {
      const result = await this.tier05CookieLookup(
        tenantId,
        fingerprint.evercookie_id,
      );
      if (result) {
        return {
          result,
          tier2TimedOut: false,
        };
      }
    }

    // Tier 1: Strong hash match
    const tier1Result = await this.tier1HashMatch(tenantId, fingerprint);
    if (tier1Result) {
      return {
        result: tier1Result,
        tier2TimedOut: false,
      };
    }

    // Tier 2: Compound filter match (with timeout)
    const { result: tier2Result, timedOut } =
      await this.tier2CompoundMatchWithTimeout(tenantId, fingerprint);
    if (tier2Result) {
      return {
        result: tier2Result,
        tier2TimedOut: timedOut,
      };
    }

    // Tier 3: Vector similarity (TODO: implement when Qdrant is deployed)

    // New device - no match found
    return {
      result: this.createNewDevice(),
      tier2TimedOut: timedOut,
    };
  }

  /**
   * Tier 0.5: Lookup by ECDSA public key (AR-64)
   * Near-perfect confidence - cryptographic identity stored in IndexedDB
   * Private key is non-extractable, so public key proves device possession
   */
  async tier05PublicKeyLookup(
    tenantId: string,
    publicKey: string,
  ): Promise<MatchResult | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.tier1IndexTable,
        Key: {
          tenant_id: { S: tenantId },
          hash_key: { S: `pubkey#${publicKey}` },
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
        evidence_codes: ["PUBLIC_KEY_MATCH"] as EvidenceCode[],
      };
    }
    return null;
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
        evidence_codes: ["EVERCOOKIE_MATCH"] as EvidenceCode[],
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
          evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
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
          evidence_codes: ["FUZZY_HASH_MATCH"] as EvidenceCode[],
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
   * Uses AbortController to cancel in-flight DynamoDB requests on timeout
   */
  async tier2CompoundMatchWithTimeout(
    tenantId: string,
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult | null; timedOut: boolean }> {
    const timeoutMs = this.deps.config.tier2TimeoutMs;
    const abortController = new AbortController();

    // Use a sentinel to distinguish timeout from null result
    const TIMEOUT_SENTINEL = Symbol("timeout");

    const raceResult = await Promise.race([
      this.tier2CompoundMatch(tenantId, fingerprint, {
        abortSignal: abortController.signal,
      }).then((r) => ({
        value: r,
        timedOut: false,
      })),
      new Promise<{ value: typeof TIMEOUT_SENTINEL; timedOut: true }>(
        (resolve) =>
          setTimeout(() => {
            abortController.abort();
            resolve({ value: TIMEOUT_SENTINEL, timedOut: true });
          }, timeoutMs),
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
   * AR-56: Applies cardinality penalty for high-traffic buckets
   */
  async tier2CompoundMatch(
    tenantId: string,
    fingerprint: Fingerprint,
    options?: { abortSignal?: AbortSignal },
  ): Promise<MatchResult | null> {
    const bucketInfos = this.buildBucketKeysWithTypes(tenantId, fingerprint);
    if (bucketInfos.length === 0) return null;

    // Query all buckets in parallel using adjacency list pattern
    // Pass abortSignal to allow cancellation on timeout
    const queries = bucketInfos.map((info) =>
      this.deps.dynamodb.send(
        new QueryCommand({
          TableName: this.deps.config.tier2BucketsTable,
          KeyConditionExpression: "bucket_key = :bk",
          ExpressionAttributeValues: {
            ":bk": { S: info.key },
          },
          ProjectionExpression: "device_id",
          Limit: TIER2_BUCKET_LIMIT,
        }),
        { abortSignal: options?.abortSignal },
      ),
    );

    // AR-56: Fetch bucket cardinalities in parallel with device queries
    const cardinalityPromise = this.fetchBucketCardinalities(
      bucketInfos.map((info) => info.key),
      options,
    );

    let results;
    let cardinalities: Map<string, number>;
    try {
      [results, cardinalities] = await Promise.all([
        Promise.all(queries),
        cardinalityPromise,
      ]);
    } catch (error) {
      // If the request was aborted, return null gracefully
      if (error instanceof Error && error.name === "AbortError") {
        return null;
      }
      throw error;
    }

    // Track which buckets each device matched in
    const candidates = this.scoreDeviceCandidatesWithEvidence(
      results,
      bucketInfos,
    );

    // Find best match (highest bucket overlap)
    let bestDeviceId: string | null = null;
    let bestScore = 0;
    let bestEvidence: EvidenceCode[] = [];

    for (const [deviceId, data] of candidates) {
      if (data.score > bestScore) {
        bestScore = data.score;
        bestDeviceId = deviceId;
        bestEvidence = data.evidenceCodes;
      }
    }

    // Require at least 2 bucket matches for confidence
    if (bestDeviceId && bestScore >= 2) {
      const profile = await this.loadProfile(tenantId, bestDeviceId);

      // AR-56: Calculate base confidence
      let confidence = Math.min(0.6 + bestScore * 0.1, 0.85);

      // AR-56: Apply cardinality penalty if any matched bucket exceeds threshold
      const highCardinalityCount = this.countHighCardinalityBuckets(
        bestEvidence,
        bucketInfos,
        cardinalities,
      );
      if (highCardinalityCount > 0) {
        // Penalize proportionally to how many buckets are high-cardinality
        const penaltyFactor =
          (highCardinalityCount / bestEvidence.length) *
          TIER2_CARDINALITY_PENALTY;
        confidence = Math.max(0.3, confidence - penaltyFactor);
      }

      return {
        device_id: bestDeviceId,
        confidence,
        match_tier: 2,
        is_new_device: false,
        risk_score: profile?.risk_score ?? 0.4,
        flags: profile?.flags ?? [],
        evidence_codes: bestEvidence,
      };
    }

    return null;
  }

  /**
   * AR-56: Fetch cardinality stats for multiple buckets using BatchGetItem
   */
  private async fetchBucketCardinalities(
    bucketKeys: string[],
    options?: { abortSignal?: AbortSignal },
  ): Promise<Map<string, number>> {
    const cardinalities = new Map<string, number>();
    if (bucketKeys.length === 0) return cardinalities;

    try {
      const result = await this.deps.dynamodb.send(
        new BatchGetItemCommand({
          RequestItems: {
            [this.deps.config.tier2BucketsTable]: {
              Keys: bucketKeys.map((key) => ({
                bucket_key: { S: key },
                device_id: { S: TIER2_STATS_SK },
              })),
              ProjectionExpression: "bucket_key, cardinality",
            },
          },
        }),
        { abortSignal: options?.abortSignal },
      );

      // Parse results
      const responses =
        result.Responses?.[this.deps.config.tier2BucketsTable] ?? [];
      for (const item of responses) {
        const unmarshalled = unmarshall(item);
        if (unmarshalled.bucket_key && unmarshalled.cardinality) {
          cardinalities.set(
            unmarshalled.bucket_key,
            unmarshalled.cardinality as number,
          );
        }
      }
    } catch (error) {
      // If aborted or error, return empty map (fail open)
      if (error instanceof Error && error.name === "AbortError") {
        return cardinalities;
      }
      // Log error but don't fail matching - cardinality check is optional
      console.warn("Failed to fetch bucket cardinalities:", error);
    }

    return cardinalities;
  }

  /**
   * AR-56: Count how many matched buckets exceed the cardinality threshold
   */
  private countHighCardinalityBuckets(
    evidenceCodes: EvidenceCode[],
    bucketInfos: { key: string; evidenceCode: EvidenceCode }[],
    cardinalities: Map<string, number>,
  ): number {
    let count = 0;
    for (const code of evidenceCodes) {
      // Find the bucket key for this evidence code
      const bucketInfo = bucketInfos.find((info) => info.evidenceCode === code);
      if (bucketInfo) {
        const cardinality = cardinalities.get(bucketInfo.key) ?? 0;
        if (cardinality > TIER2_HIGH_CARDINALITY_THRESHOLD) {
          count++;
        }
      }
    }
    return count;
  }

  /**
   * Build compound bucket keys for Tier 2 matching
   */
  buildBucketKeys(tenantId: string, fingerprint: Fingerprint): string[] {
    return this.buildBucketKeysWithTypes(tenantId, fingerprint).map(
      (info) => info.key,
    );
  }

  /**
   * Build compound bucket keys with their evidence code types
   * AR-54: Used for evidence tracking in match results
   */
  private buildBucketKeysWithTypes(
    tenantId: string,
    fingerprint: Fingerprint,
  ): { key: string; evidenceCode: EvidenceCode }[] {
    const buckets: { key: string; evidenceCode: EvidenceCode }[] = [];

    // IP + JA4 (network identity)
    if (fingerprint.ip_address && fingerprint.ja4) {
      buckets.push({
        key: `${tenantId}#ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`,
        evidenceCode: "IP_JA4_BUCKET",
      });
    }

    // GPU + Screen + Timezone (hardware/locale identity)
    if (
      fingerprint.gpu_renderer &&
      fingerprint.screen_dims &&
      fingerprint.timezone
    ) {
      buckets.push({
        key: `${tenantId}#gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`,
        evidenceCode: "GPU_SCREEN_TZ_BUCKET",
      });
    }

    // Audio + Canvas (rendering identity)
    if (fingerprint.audio_hash && fingerprint.canvas_hash) {
      buckets.push({
        key: `${tenantId}#audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`,
        evidenceCode: "AUDIO_CANVAS_BUCKET",
      });
    }

    return buckets;
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
   * Score device candidates and track which buckets matched
   * AR-54: Used to populate evidence_codes in match results
   */
  private scoreDeviceCandidatesWithEvidence(
    results: QueryCommandOutput[],
    bucketInfos: { key: string; evidenceCode: EvidenceCode }[],
  ): Map<string, { score: number; evidenceCodes: EvidenceCode[] }> {
    const candidates = new Map<
      string,
      { score: number; evidenceCodes: Set<EvidenceCode> }
    >();

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const evidenceCode = bucketInfos[i].evidenceCode;

      if (result.Items && result.Items.length > 0) {
        for (const item of result.Items) {
          const unmarshalled = unmarshall(item);
          const deviceId = unmarshalled.device_id;
          if (deviceId) {
            const existing = candidates.get(deviceId);
            if (existing) {
              existing.score += 1;
              existing.evidenceCodes.add(evidenceCode);
            } else {
              candidates.set(deviceId, {
                score: 1,
                evidenceCodes: new Set([evidenceCode]),
              });
            }
          }
        }
      }
    }

    // Convert Sets to arrays for the return value
    const result = new Map<
      string,
      { score: number; evidenceCodes: EvidenceCode[] }
    >();
    for (const [deviceId, data] of candidates) {
      result.set(deviceId, {
        score: data.score,
        evidenceCodes: Array.from(data.evidenceCodes),
      });
    }

    return result;
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
   * AR-55: confidence is 0 since no match occurred (confidence = match confidence)
   */
  createNewDevice(): MatchResult {
    const deviceId = `dev_${generateUUID()}`;
    return {
      device_id: deviceId,
      confidence: 0, // AR-55: No match confidence for new devices
      match_tier: -1,
      is_new_device: true,
      risk_score: 0.5, // Neutral for new devices
      flags: [],
      evidence_codes: ["NEW_DEVICE"],
    };
  }

  /**
   * Write match result to session cache (AR-52: DynamoDB replaces Redis)
   */
  async writeMatchResult(
    sessionId: string,
    result: MatchResult,
    idempotencyKey: string,
  ): Promise<void> {
    const value: SessionCacheValue = {
      status: "complete",
      device_id: result.device_id,
      risk_score: result.risk_score,
      confidence: result.confidence,
      match_tier: result.match_tier,
      match_version: Date.now(),
      idempotency_key: idempotencyKey,
      flags: result.flags,
      evidence_codes: result.evidence_codes, // AR-54
      updated_at: Date.now(),
    };

    // DynamoCacheService handles conditional write (only updates if confidence is higher)
    await this.deps.cache.writeSessionCache(sessionId, value);
  }

  /**
   * Write degraded status to cache when matching fails (AR-52: DynamoDB replaces Redis)
   */
  async writeDegradedResult(
    sessionId: string,
    idempotencyKey: string,
  ): Promise<void> {
    const value: SessionCacheValue = {
      status: "degraded",
      device_id: "",
      risk_score: 0.5,
      confidence: 0,
      match_tier: -1,
      match_version: Date.now(),
      idempotency_key: idempotencyKey,
      flags: ["matching_failed"],
      evidence_codes: [], // AR-54: No evidence when matching fails
      updated_at: Date.now(),
    };

    await this.deps.cache.writeSessionCache(sessionId, value);
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
 * Generate idempotency key from session and fingerprint data
 * Uses FNV-1a hash (AR-32: consolidated from helpers/hash.ts)
 */
export function generateIdempotencyKey(
  sessionId: string,
  fingerprint: Fingerprint,
): string {
  const input = `${sessionId}:${fingerprint.stable_hash ?? ""}:${fingerprint.canvas_hash ?? ""}`;
  return fnv1a(input);
}

/**
 * Generate a cryptographically secure UUID v4
 * Uses Node.js crypto module for secure random generation
 */
export function generateUUID(): string {
  return randomUUID();
}
