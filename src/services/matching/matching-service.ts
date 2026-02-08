import { ulid } from "ulid";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import type { Pool } from "pg";
import { DynamoCacheService } from "../cache";
import { pgUnifiedMatch } from "../postgres";
import { Fingerprint, FingerprintPayload, MatchResult } from "./types";
import { MatchTier } from "../../types/matching-tiers";
import {
  PRIVACY_BROWSER_PENALTY,
  PRIVATE_BROWSING_PENALTY,
} from "../../helpers/constants";
import { fnv1a } from "../../helpers/hash";

import {
  writeMatchResult as cacheWriteMatchResult,
  writeDegradedResult as cacheWriteDegradedResult,
  SessionCacheDeps,
} from "./session-cache";
import type { SessionAnomalySignal } from "./types";
import {
  publicKeyLookup,
  cookieLookup,
  sigintIdLookup,
  IndexLookupDeps,
} from "./index-lookup";
import {
  vectorMatchWithTimeout,
  upsertDeviceVector,
  VectorMatchDeps,
} from "./vector-match";
import {
  sessionAnchorLookup,
  ipUaAnchorLookup,
  SessionAnchorDeps,
} from "./session-anchors";

export interface MatchingServiceConfig {
  tier1IndexTable: string;
  tier2BucketsTable: string;
  profilesTable: string;
  profileQueueUrl: string;
  sessionTtlSeconds: number;
  tier2TimeoutMs: number;
  vectorWorkerArn?: string;
  vectorCollection?: string;
}

export interface MatchingServiceDeps {
  dynamodb: DynamoDBClient;
  sqs: SQSClient;
  cache: DynamoCacheService;
  config: MatchingServiceConfig;
  lambda?: LambdaClient;
  logger?: Logger;
  metrics?: Metrics;
  /** PostgreSQL pool for T1/T1.5 matching (required for hash + SimHash) */
  pgPool?: Pool;
}

export class MatchingService {
  private cacheDeps: SessionCacheDeps;
  private indexLookupDeps: IndexLookupDeps;
  private vectorDeps: VectorMatchDeps | null;
  private anchorDeps: SessionAnchorDeps;
  private readonly useVectorSearch: boolean;
  private readonly pgPool: Pool | null;

  constructor(private deps: MatchingServiceDeps) {
    this.pgPool = deps.pgPool ?? null;
    this.cacheDeps = { cache: deps.cache };
    this.indexLookupDeps = {
      dynamodb: deps.dynamodb,
      tier1IndexTable: deps.config.tier1IndexTable,
    };
    this.anchorDeps = {
      dynamodb: deps.dynamodb,
      tier2BucketsTable: deps.config.tier2BucketsTable,
      profilesTable: deps.config.profilesTable,
    };

    const { vectorWorkerArn, vectorCollection } = deps.config;
    const { lambda, logger, metrics } = deps;
    if (vectorWorkerArn && vectorCollection && lambda && logger && metrics) {
      this.useVectorSearch = true;
      this.vectorDeps = {
        lambda,
        dynamodb: deps.dynamodb,
        vectorWorkerArn,
        collection: vectorCollection,
        profilesTable: deps.config.profilesTable,
        logger,
        metrics,
      };
    } else {
      this.useVectorSearch = false;
      this.vectorDeps = null;
    }
  }

  get cache(): DynamoCacheService {
    return this.deps.cache;
  }

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

  private async runIdentityLookups(
    fingerprint: Fingerprint,
  ): Promise<MatchResult | null> {
    const fuzzyHash = fingerprint.fuzzy_hash;
    const lookups: [string | undefined, typeof publicKeyLookup][] = [
      [fingerprint.public_key, publicKeyLookup],
      [fingerprint.evercookie_id, cookieLookup],
      [fingerprint.sigint_id, sigintIdLookup],
    ];
    for (const [id, fn] of lookups) {
      if (id) {
        const r = await fn(this.indexLookupDeps, id, fuzzyHash);
        if (r) return r;
      }
    }
    return null;
  }

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

  /** Waterfall: identity → PG unified (hash + simhash) → vector → anchors → new device */
  async runTieredMatching(
    fingerprint: Fingerprint,
  ): Promise<{ result: MatchResult; tier2TimedOut: boolean }> {
    const identityResult = await this.runIdentityLookups(fingerprint);
    if (identityResult) return this.wrapResult(identityResult, fingerprint);

    // T1 + T1.5: unified PostgreSQL query (stable hash + SimHash LSH)
    // Always capture pgQueryContext for archive, even when no match
    let pgQueryContext: MatchResult["pg_query_context"];
    if (this.pgPool) {
      const { match, pgQueryContext: ctx } = await pgUnifiedMatch(
        this.pgPool,
        fingerprint,
      );
      pgQueryContext = ctx;
      if (match) {
        match.pg_query_context = pgQueryContext;
        return this.wrapResult(match, fingerprint);
      }
    }

    // Tier 2: Vector similarity search (requires vector infrastructure)
    let tier2Result: MatchResult | null = null;
    let timedOut = false;

    if (this.useVectorSearch && this.vectorDeps) {
      const vectorResult = await vectorMatchWithTimeout(
        this.vectorDeps,
        fingerprint,
      );
      tier2Result = vectorResult.result;
      timedOut = vectorResult.timedOut;
      if (tier2Result) {
        tier2Result.pg_query_context = pgQueryContext;
        return this.wrapResult(tier2Result, fingerprint, timedOut);
      }
    }

    const sessionResult = await sessionAnchorLookup(
      this.anchorDeps,
      fingerprint,
    );
    if (sessionResult) {
      sessionResult.pg_query_context = pgQueryContext;
      return this.wrapResult(sessionResult, fingerprint, timedOut);
    }

    const ipUaResult = await ipUaAnchorLookup(this.anchorDeps, fingerprint);
    if (ipUaResult) {
      ipUaResult.pg_query_context = pgQueryContext;
      return this.wrapResult(ipUaResult, fingerprint, timedOut);
    }

    const newDevice = this.createNewDevice();
    newDevice.pg_query_context = pgQueryContext;
    return { result: newDevice, tier2TimedOut: timedOut };
  }

  createNewDevice(): MatchResult {
    const deviceId = `dev_${ulid()}`;
    return {
      device_id: deviceId,
      confidence: 0,
      match_tier: MatchTier.NEW_DEVICE,
      is_new_device: true,
      risk_score: 0.5,
      flags: [],
      evidence_codes: ["NEW_DEVICE"],
    };
  }

  writeMatchResult(params: {
    sessionId: string;
    result: MatchResult;
    idempotencyKey: string;
    anomalies?: SessionAnomalySignal[];
  }): Promise<boolean> {
    return cacheWriteMatchResult(this.cacheDeps, params); // eslint-disable-line no-restricted-syntax
  }

  writeDegradedResult(
    sessionId: string,
    idempotencyKey: string,
  ): Promise<boolean> {
    return cacheWriteDegradedResult(this.cacheDeps, sessionId, idempotencyKey); // eslint-disable-line no-restricted-syntax
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

  /** No-op if vector search is not configured. */
  async upsertVector(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    if (!this.useVectorSearch || !this.vectorDeps) {
      return true; // Vector not configured, skip silently
    }

    return upsertDeviceVector(this.vectorDeps, deviceId, fingerprint);
  }
}

export function generateIdempotencyKey(
  sessionId: string,
  fingerprint: Fingerprint,
): string {
  const input = `${sessionId}:${fingerprint.stable_hash ?? ""}:${fingerprint.canvas_hash ?? ""}`;
  return fnv1a(input);
}
