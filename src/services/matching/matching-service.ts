import { ulid } from "ulid";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { DynamoCacheService } from "../cache";
import { Fingerprint, FingerprintPayload, MatchResult } from "./types";
import {
  PRIVACY_BROWSER_PENALTY,
  PRIVATE_BROWSING_PENALTY,
} from "../../helpers/constants";
import { fnv1a } from "../../helpers/hash";

import {
  writeMatchResult as tier0WriteMatchResult,
  writeDegradedResult as tier0WriteDegradedResult,
  Tier0CacheDeps,
} from "./tier0-cache";
import type { SessionAnomalySignal } from "./types";
import {
  tier05PublicKeyLookup,
  tier05CookieLookup,
  tier05SigintIdLookup,
  Tier05IdentityDeps,
} from "./tier05-identity";
import { tier1HashMatch, Tier1HashDeps } from "./tier1-hash";
import { tier15SimHashMatch, Tier15SimHashDeps } from "./tier15-simhash";
import {
  tier2VectorMatchWithTimeout,
  upsertDeviceVector,
  Tier2VectorDeps,
} from "./tier2-vector";
import {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  SessionAnchorDeps,
} from "./session-anchors";

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
  /** Optional: Vector worker Lambda ARN for Tier 2 vector search */
  vectorWorkerArn?: string;
  /** Optional: Qdrant collection name for fingerprint vectors */
  vectorCollection?: string;
}

/**
 * Dependencies injected into the matching service
 */
export interface MatchingServiceDeps {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  cache: DynamoCacheService;
  config: MatchingServiceConfig;
  /** Optional: Lambda client for vector search (required if vectorWorkerArn set) */
  lambda?: LambdaClient;
  /** Logger for vector operations */
  logger?: Logger;
  /** Metrics for vector operations */
  metrics?: Metrics;
}

/**
 * Matching service handles device fingerprint matching logic
 * Uses tiered matching strategy:
 * - Tier 0: DynamoDB session cache hit
 * - Tier 0.5: Evercookie/cookie lookup, public key, sigint
 * - Tier 1: Strong hash match (stable_hash, fuzzy_hash)
 * - Tier 1.5: SimHash LSH match (fuzzy_hash drift detection)
 * - Tier 2: Vector similarity match (Qdrant)
 * - Session anchors: IP+UA+Screen, IP+UA fallback
 * - New Device: Create new device_id
 */
export class MatchingService {
  private tier0Deps: Tier0CacheDeps;
  private tier05Deps: Tier05IdentityDeps;
  private tier1Deps: Tier1HashDeps;
  private tier15Deps: Tier15SimHashDeps;
  private tier2VectorDeps: Tier2VectorDeps | null;
  private anchorDeps: SessionAnchorDeps;
  /** Whether vector search is enabled for Tier 2 */
  private readonly useVectorSearch: boolean;

  constructor(private deps: MatchingServiceDeps) {
    this.tier0Deps = { cache: deps.cache };
    this.tier05Deps = {
      dynamodb: deps.dynamodb,
      tier1IndexTable: deps.config.tier1IndexTable,
    };
    this.tier1Deps = {
      dynamodb: deps.dynamodb,
      tier1IndexTable: deps.config.tier1IndexTable,
    };
    // Tier 1.5 SimHash LSH uses tier2BucketsTable for band storage
    this.tier15Deps = {
      dynamodb: deps.dynamodb,
      tier2BucketsTable: deps.config.tier2BucketsTable,
    };
    this.anchorDeps = {
      dynamodb: deps.dynamodb,
      tier2BucketsTable: deps.config.tier2BucketsTable,
      profilesTable: deps.config.profilesTable,
    };

    // Configure vector search if ARN is provided
    this.useVectorSearch = !!(
      deps.config.vectorWorkerArn &&
      deps.config.vectorCollection &&
      deps.lambda &&
      deps.logger &&
      deps.metrics
    );

    if (this.useVectorSearch) {
      this.tier2VectorDeps = {
        lambda: deps.lambda!,
        dynamodb: deps.dynamodb,
        vectorWorkerArn: deps.config.vectorWorkerArn!,
        collection: deps.config.vectorCollection!,
        profilesTable: deps.config.profilesTable,
        logger: deps.logger!,
        metrics: deps.metrics!,
      };
    } else {
      this.tier2VectorDeps = null;
    }
  }

  /** Exposes the cache service for direct session lookups */
  get cache(): DynamoCacheService {
    return this.deps.cache;
  }

  /**
   * Apply confidence penalty for privacy-enhanced browsers
   * Reduces confidence score when privacy browser or private browsing is detected
   * @param result - The match result to adjust
   * @param fingerprint - The fingerprint containing privacy signals
   * @returns Adjusted match result with reduced confidence if applicable
   */
  applyPrivacyPenalty(
    result: MatchResult,
    fingerprint: Fingerprint,
  ): MatchResult {
    let penalty = 0;
    if (fingerprint.privacy_browser) penalty += PRIVACY_BROWSER_PENALTY;
    if (fingerprint.is_private_browsing) penalty += PRIVATE_BROWSING_PENALTY;
    if (penalty === 0) return result;
    return { ...result, confidence: Math.max(0, result.confidence - penalty) };
  }

  /**
   * Run Tier 0.5 identity lookups (public key, evercookie, sigint)
   * @param fingerprint - The fingerprint containing identity signals
   * @returns Match result if an identity match is found, null otherwise
   */
  private async runTier05Lookups(
    fingerprint: Fingerprint,
  ): Promise<MatchResult | null> {
    const fuzzyHash = fingerprint.fuzzy_hash;
    const lookups: [string | undefined, typeof tier05PublicKeyLookup][] = [
      [fingerprint.public_key, tier05PublicKeyLookup],
      [fingerprint.evercookie_id, tier05CookieLookup],
      [fingerprint.sigint_id, tier05SigintIdLookup],
    ];
    for (const [id, fn] of lookups) {
      if (id) {
        const r = await fn(this.tier05Deps, id, fuzzyHash);
        if (r) return r;
      }
    }
    return null;
  }

  /**
   * Wrap a match result with privacy penalty applied and timeout flag
   * @param match - The raw match result
   * @param fingerprint - The fingerprint for privacy penalty calculation
   * @param timedOut - Whether tier 2 matching timed out
   * @returns Wrapped result with adjusted confidence and timeout flag
   */
  private wrapResult(
    match: MatchResult,
    fingerprint: Fingerprint,
    timedOut = false,
  ) {
    return {
      result: this.applyPrivacyPenalty(match, fingerprint),
      tier2TimedOut: timedOut,
    };
  }

  /**
   * Run the full tiered matching pipeline
   * Executes tiers in order: 0.5 (identity) → 1 (hash) → 1.5 (simhash) → 2 (vector OR compound) → anchors → new device
   * @param fingerprint - The fingerprint to match against existing devices
   * @returns Match result and flag indicating if tier 2 timed out
   */
  async runTieredMatching(
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult; tier2TimedOut: boolean }> {
    const tier05Result = await this.runTier05Lookups(fingerprint);
    if (tier05Result) return this.wrapResult(tier05Result, fingerprint);

    const tier1Result = await tier1HashMatch(this.tier1Deps, fingerprint);
    if (tier1Result) return this.wrapResult(tier1Result, fingerprint);

    const tier15Result = await tier15SimHashMatch(this.tier15Deps, fingerprint);
    if (tier15Result) return this.wrapResult(tier15Result, fingerprint);

    // Tier 2: Vector similarity search (requires vector infrastructure)
    let tier2Result: MatchResult | null = null;
    let timedOut = false;

    if (this.useVectorSearch && this.tier2VectorDeps) {
      const vectorResult = await tier2VectorMatchWithTimeout(
        this.tier2VectorDeps,
        fingerprint,
      );
      tier2Result = vectorResult.result;
      timedOut = vectorResult.timedOut;
      if (tier2Result)
        return this.wrapResult(tier2Result, fingerprint, timedOut);
    }

    const sessionResult = await sessionAnchorLookup(
      this.anchorDeps,
      fingerprint,
    );
    if (sessionResult)
      return this.wrapResult(sessionResult, fingerprint, timedOut);

    const ipUaResult = await ipUaAnchorLookup(this.anchorDeps, fingerprint);
    if (ipUaResult) return this.wrapResult(ipUaResult, fingerprint, timedOut);

    return { result: this.createNewDevice(), tier2TimedOut: timedOut };
  }

  /**
   * Create a new device result with a fresh device ID
   * @returns Match result for a newly created device
   */
  createNewDevice(): MatchResult {
    const deviceId = `dev_${ulid()}`;
    return {
      device_id: deviceId,
      confidence: 0,
      match_tier: -1,
      is_new_device: true,
      risk_score: 0.5,
      flags: [],
      evidence_codes: ["NEW_DEVICE"],
    };
  }

  /**
   * Write match result to session cache
   * @returns true if written, false if skipped (higher confidence exists)
   */
  writeMatchResult(params: {
    sessionId: string;
    result: MatchResult;
    idempotencyKey: string;
    anomalies?: SessionAnomalySignal[];
  }): Promise<boolean> {
    return tier0WriteMatchResult(this.tier0Deps, params);
  }

  /**
   * Write degraded status to session cache
   * @returns true if written, false if skipped (higher confidence exists)
   */
  writeDegradedResult(
    sessionId: string,
    idempotencyKey: string,
  ): Promise<boolean> {
    return tier0WriteDegradedResult(this.tier0Deps, sessionId, idempotencyKey);
  }

  /**
   * Queue a profile update to SQS for async processing
   * @param deviceId - The device ID to update
   * @param payload - The fingerprint payload with sigint and TLS data
   * @param isNewDevice - Whether this is a newly created device
   * @param matchResult - Optional match result for tier-gated identity association
   */
  async queueProfileUpdate(
    deviceId: string,
    payload: FingerprintPayload,
    isNewDevice: boolean = false,
    matchResult?: MatchResult,
  ): Promise<void> {
    await this.deps.sqs.send(
      new SendMessageCommand({
        QueueUrl: this.deps.config.profileQueueUrl,
        MessageBody: JSON.stringify({
          device_id: deviceId,
          fingerprint: payload.fingerprint,
          sigint: payload.sigint,
          tcp_blob: payload.tcp_blob,
          tls_blob: payload.tls_blob,
          timestamp: payload.timestamp,
          is_new_device: isNewDevice,
          // Include match context for tier-gated identity association
          ...(matchResult && {
            match_tier: matchResult.match_tier,
            evidence_codes: matchResult.evidence_codes,
          }),
        }),
      }),
    );
  }

  /**
   * Upsert a device's vector embedding to Qdrant.
   * Called after matching to store/update the device's fingerprint vector.
   * No-op if vector search is not configured.
   *
   * @param deviceId - Device ID to upsert
   * @param fingerprint - Fingerprint to compute embedding from
   * @returns true if upsert succeeded or vector not configured, false on error
   */
  async upsertVector(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    if (!this.useVectorSearch || !this.tier2VectorDeps) {
      return true; // Vector not configured, skip silently
    }

    return upsertDeviceVector(this.tier2VectorDeps, deviceId, fingerprint);
  }
}

/**
 * Generate idempotency key from session and fingerprint data
 * Used to deduplicate concurrent requests for the same session
 * @param sessionId - The session identifier
 * @param fingerprint - The fingerprint containing hash values
 * @returns FNV-1a hash of the combined session and fingerprint data
 */
export function generateIdempotencyKey(
  sessionId: string,
  fingerprint: Fingerprint,
): string {
  const input = `${sessionId}:${fingerprint.stable_hash ?? ""}:${fingerprint.canvas_hash ?? ""}`;
  return fnv1a(input);
}
