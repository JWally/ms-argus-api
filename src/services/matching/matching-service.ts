// src/services/matching/matching-service.ts
import { ulid } from "ulid";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { DynamoCacheService } from "../cache";
import {
  Fingerprint,
  FingerprintPayload,
  MatchResult,
  SessionCacheValue,
} from "./types";
import {
  PRIVACY_BROWSER_PENALTY,
  PRIVATE_BROWSING_PENALTY,
} from "../../helpers/constants";
import { fnv1a } from "../../helpers/hash";

// Tier module imports
import {
  checkCache as tier0CheckCache,
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
  tier2CompoundMatchWithTimeout,
  loadProfile,
  Tier2CompoundDeps,
} from "./tier2-compound";
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
}

/**
 * Dependencies injected into the matching service
 */
export interface MatchingServiceDeps {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  cache: DynamoCacheService;
  config: MatchingServiceConfig;
}

/**
 * Matching service handles device fingerprint matching logic
 * Uses tiered matching strategy:
 * - Tier 0: DynamoDB session cache hit
 * - Tier 0.5: Evercookie/cookie lookup, public key, sigint
 * - Tier 1: Strong hash match (stable_hash, fuzzy_hash)
 * - Tier 1.5: SimHash LSH match (fuzzy_hash drift detection)
 * - Tier 2: Compound filter match (ip+ja4, gpu+screen+tz, etc)
 * - New Device: Create new device_id
 */
export class MatchingService {
  private tier0Deps: Tier0CacheDeps;
  private tier05Deps: Tier05IdentityDeps;
  private tier1Deps: Tier1HashDeps;
  private tier15Deps: Tier15SimHashDeps;
  private tier2Deps: Tier2CompoundDeps;
  private anchorDeps: SessionAnchorDeps;

  constructor(private deps: MatchingServiceDeps) {
    // Initialize tier-specific dependencies
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
    this.tier2Deps = {
      dynamodb: deps.dynamodb,
      tier2BucketsTable: deps.config.tier2BucketsTable,
      profilesTable: deps.config.profilesTable,
      tier2TimeoutMs: deps.config.tier2TimeoutMs,
    };
    this.anchorDeps = {
      dynamodb: deps.dynamodb,
      tier2BucketsTable: deps.config.tier2BucketsTable,
      profilesTable: deps.config.profilesTable,
    };
  }

  /** Check if session is already cached */
  checkCache(sessionId: string): Promise<SessionCacheValue | null> {
    return tier0CheckCache(this.tier0Deps, sessionId);
  }

  /** Apply confidence penalty for privacy browser detection */
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

  /** Run tiered matching strategy */
  async runTieredMatching(
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult; tier2TimedOut: boolean }> {
    // Pass fuzzy_hash to tier05 lookups for drift detection
    const incomingFuzzyHash = fingerprint.fuzzy_hash;

    // Tier 0.5: Cryptographic identity lookup (highest confidence)
    if (fingerprint.public_key) {
      const result = await tier05PublicKeyLookup(
        this.tier05Deps,
        fingerprint.public_key,
        incomingFuzzyHash,
      );
      if (result) {
        return {
          result: this.applyPrivacyPenalty(result, fingerprint),
          tier2TimedOut: false,
        };
      }
    }

    // Tier 0.5: Evercookie lookup
    if (fingerprint.evercookie_id) {
      const result = await tier05CookieLookup(
        this.tier05Deps,
        fingerprint.evercookie_id,
        incomingFuzzyHash,
      );
      if (result) {
        return {
          result: this.applyPrivacyPenalty(result, fingerprint),
          tier2TimedOut: false,
        };
      }
    }

    // Tier 0.5: Sigint ID lookup
    if (fingerprint.sigint_id) {
      const result = await tier05SigintIdLookup(
        this.tier05Deps,
        fingerprint.sigint_id,
        incomingFuzzyHash,
      );
      if (result) {
        return {
          result: this.applyPrivacyPenalty(result, fingerprint),
          tier2TimedOut: false,
        };
      }
    }

    // Tier 1: Strong hash match
    const tier1Result = await tier1HashMatch(this.tier1Deps, fingerprint);
    if (tier1Result) {
      return {
        result: this.applyPrivacyPenalty(tier1Result, fingerprint),
        tier2TimedOut: false,
      };
    }

    // Tier 1.5: SimHash LSH match (same-browser drift detection)
    // Uses fuzzy_hash with locality-sensitive hashing for efficient similarity search
    const tier15Result = await tier15SimHashMatch(this.tier15Deps, fingerprint);
    if (tier15Result) {
      return {
        result: this.applyPrivacyPenalty(tier15Result, fingerprint),
        tier2TimedOut: false,
      };
    }

    // Tier 2: Compound filter match (with timeout)
    const { result: tier2Result, timedOut } =
      await tier2CompoundMatchWithTimeout(this.tier2Deps, fingerprint);
    if (tier2Result) {
      return {
        result: this.applyPrivacyPenalty(tier2Result, fingerprint),
        tier2TimedOut: timedOut,
      };
    }

    // Session anchor lookup
    const sessionAnchorResult = await sessionAnchorLookup(
      this.anchorDeps,
      fingerprint,
    );
    if (sessionAnchorResult) {
      return {
        result: this.applyPrivacyPenalty(sessionAnchorResult, fingerprint),
        tier2TimedOut: timedOut,
      };
    }

    // IP+UA anchor lookup
    const ipUaAnchorResult = await ipUaAnchorLookup(
      this.anchorDeps,
      fingerprint,
    );
    if (ipUaAnchorResult) {
      return {
        result: this.applyPrivacyPenalty(ipUaAnchorResult, fingerprint),
        tier2TimedOut: timedOut,
      };
    }

    // New device - no match found
    return { result: this.createNewDevice(), tier2TimedOut: timedOut };
  }

  // Delegate methods to tier modules for backward compatibility
  // Added optional incomingFuzzyHash for drift detection
  tier05PublicKeyLookup(
    publicKey: string,
    incomingFuzzyHash?: string,
  ): Promise<MatchResult | null> {
    return tier05PublicKeyLookup(this.tier05Deps, publicKey, incomingFuzzyHash);
  }

  tier05CookieLookup(
    evercookieId: string,
    incomingFuzzyHash?: string,
  ): Promise<MatchResult | null> {
    return tier05CookieLookup(this.tier05Deps, evercookieId, incomingFuzzyHash);
  }

  tier05SigintIdLookup(
    sigintId: string,
    incomingFuzzyHash?: string,
  ): Promise<MatchResult | null> {
    return tier05SigintIdLookup(this.tier05Deps, sigintId, incomingFuzzyHash);
  }

  tier1HashMatch(fingerprint: Fingerprint): Promise<MatchResult | null> {
    return tier1HashMatch(this.tier1Deps, fingerprint);
  }

  /** SimHash LSH match for same-browser drift detection */
  tier15SimHashMatch(fingerprint: Fingerprint): Promise<MatchResult | null> {
    return tier15SimHashMatch(this.tier15Deps, fingerprint);
  }

  tier2CompoundMatchWithTimeout(
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult | null; timedOut: boolean }> {
    return tier2CompoundMatchWithTimeout(this.tier2Deps, fingerprint);
  }

  async tier2CompoundMatch(
    fingerprint: Fingerprint,
    options?: { abortSignal?: AbortSignal },
  ): Promise<MatchResult | null> {
    // Import inline to avoid circular deps
    const { tier2CompoundMatch } = await import("./tier2-compound");
    return tier2CompoundMatch(this.tier2Deps, fingerprint, options);
  }

  sessionAnchorLookup(fingerprint: Fingerprint): Promise<MatchResult | null> {
    return sessionAnchorLookup(this.anchorDeps, fingerprint);
  }

  ipUaAnchorLookup(fingerprint: Fingerprint): Promise<MatchResult | null> {
    return ipUaAnchorLookup(this.anchorDeps, fingerprint);
  }

  loadProfile(
    deviceId: string,
  ): Promise<{ risk_score: number; flags: string[] } | null> {
    return loadProfile(this.tier2Deps, deviceId);
  }

  createNewDevice(): MatchResult {
    // Use ULID for time-sortable device IDs
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
   * Returns boolean indicating if write succeeded
   * @returns true if written, false if skipped (higher confidence exists)
   */
  writeMatchResult(
    sessionId: string,
    result: MatchResult,
    idempotencyKey: string,
    anomalies?: SessionAnomalySignal[],
  ): Promise<boolean> {
    return tier0WriteMatchResult(
      this.tier0Deps,
      sessionId,
      result,
      idempotencyKey,
      anomalies,
    );
  }

  /**
   * Write degraded status to session cache
   * Returns boolean indicating if write succeeded
   * @returns true if written, false if skipped (higher confidence exists)
   */
  writeDegradedResult(
    sessionId: string,
    idempotencyKey: string,
  ): Promise<boolean> {
    return tier0WriteDegradedResult(this.tier0Deps, sessionId, idempotencyKey);
  }

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
}

/** Generate idempotency key from session and fingerprint data */
export function generateIdempotencyKey(
  sessionId: string,
  fingerprint: Fingerprint,
): string {
  const input = `${sessionId}:${fingerprint.stable_hash ?? ""}:${fingerprint.canvas_hash ?? ""}`;
  return fnv1a(input);
}
