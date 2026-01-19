// src/services/profile/profile-service.ts
// AR-52: Replaced Redis with DynamoDB session cache
// AR-120: Refactored to orchestration-only, delegates to focused modules
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { DynamoCacheService } from "../cache";
import { Fingerprint, ProfileUpdatePayload, DeviceProfile } from "./types";
import { hasSignificantDrift } from "./drift-detection";
import {
  detectBotSignals,
  computeFlags,
  computeRiskScore,
} from "./flag-computation";
import {
  buildTier1IndexEntries,
  buildIdentityIndexEntries,
  buildHashIndexEntries,
  batchWriteTier1Indexes,
  buildTier2BucketKeys,
  batchWriteTier2Buckets,
  incrementBucketCardinalities,
  buildSessionAnchorKey,
  writeSessionAnchorBucket,
  buildIpUaAnchorKey,
  writeIpUaAnchorBucket,
  Tier1IndexEntry,
  IndexWriterDeps,
  ASSOCIATION_ALLOWED_EVIDENCE,
} from "./index-writers";

/**
 * Configuration for the profile service
 */
export interface ProfileServiceConfig {
  profilesTable: string;
  tier1IndexTable: string;
  tier2BucketsTable: string;
  profileTtlDays: number;
  tier2BucketTtlDays: number;
  mutationGateTtlSeconds: number;
}

/**
 * Dependencies injected into the profile service
 */
export interface ProfileServiceDeps {
  dynamodb: DynamoDBClient;
  cache: DynamoCacheService; // AR-52: DynamoDB cache replaces Redis
  config: ProfileServiceConfig;
}

/**
 * Profile service handles device profile updates
 * Implements mutation gating to reduce unnecessary writes
 * AR-120: Orchestration-only - delegates to focused modules
 */
export class ProfileService {
  private indexWriterDeps: IndexWriterDeps;

  constructor(private deps: ProfileServiceDeps) {
    // Create index writer deps from service deps
    this.indexWriterDeps = {
      dynamodb: deps.dynamodb,
      tier1IndexTable: deps.config.tier1IndexTable,
      tier2BucketsTable: deps.config.tier2BucketsTable,
    };
  }

  /**
   * Atomically try to acquire the mutation gate for a device
   * Uses DynamoDB conditional write to avoid TOCTOU race condition (AR-27, AR-52)
   * Returns true if gate was acquired (we should update), false if already held
   */
  async tryAcquireMutationGate(deviceId: string): Promise<boolean> {
    return this.deps.cache.tryAcquireMutationGate(deviceId);
  }

  /**
   * Load existing device profile from DynamoDB
   */
  async loadExistingProfile(deviceId: string): Promise<DeviceProfile | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.profilesTable,
        Key: {
          device_id: { S: deviceId },
        },
      }),
    );

    if (result.Item) {
      return unmarshall(result.Item) as DeviceProfile;
    }
    return null;
  }

  /**
   * AR-120: Delegates to drift-detection module
   */
  hasSignificantDrift(existing: DeviceProfile, incoming: Fingerprint): boolean {
    return hasSignificantDrift(existing, incoming);
  }

  /**
   * AR-120: Delegates to flag-computation module
   */
  detectBotSignals(fingerprint: Fingerprint): string[] {
    return detectBotSignals(fingerprint);
  }

  /**
   * AR-120: Delegates to flag-computation module
   * AR-145: Added raw parameter for cross-field anomaly detection
   */
  computeFlags(
    fingerprint: Fingerprint,
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean,
    hasDrift: boolean,
    raw?: unknown,
  ): string[] {
    return computeFlags(
      fingerprint,
      existingProfile,
      isNewDevice,
      hasDrift,
      raw,
    );
  }

  /**
   * AR-120: Delegates to flag-computation module
   */
  computeRiskScore(
    flags: string[],
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean,
  ): number {
    return computeRiskScore(flags, existingProfile, isNewDevice);
  }

  /**
   * Update device profile in DynamoDB
   * AR-145: Added rawFingerprint for cross-field anomaly detection
   */
  async updateProfile(
    deviceId: string,
    fingerprint: Fingerprint,
    timestamp: number,
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean = false,
    hasDrift: boolean = false,
    rawFingerprint?: unknown,
  ): Promise<void> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;
    const now = Date.now();

    // Only update last_seen if hour changed (reduce write amplification)
    const currentHour = Math.floor(now / 3600000);
    const existingHour = existingProfile
      ? Math.floor(existingProfile.last_seen_at / 3600000)
      : 0;
    const shouldUpdateLastSeen = currentHour !== existingHour;

    // Compute flags based on fingerprint and profile state
    // AR-145: Pass raw fingerprint for cross-field anomaly detection
    const flags = this.computeFlags(
      fingerprint,
      existingProfile,
      isNewDevice,
      hasDrift,
      rawFingerprint,
    );

    const profileData: Record<string, unknown> = {
      device_id: deviceId,
      ...fingerprint,
      first_seen_at: existingProfile?.first_seen_at ?? now,
      last_seen_at: shouldUpdateLastSeen
        ? now
        : (existingProfile?.last_seen_at ?? now),
      request_count: (existingProfile?.request_count ?? 0) + 1,
      updated_at: now,
      ttl,
      flags,
    };

    // Compute risk score based on flags and profile history
    profileData.risk_score = this.computeRiskScore(
      flags,
      existingProfile,
      isNewDevice,
    );

    await this.deps.dynamodb.send(
      new PutItemCommand({
        TableName: this.deps.config.profilesTable,
        Item: marshall(profileData, { removeUndefinedValues: true }),
      }),
    );
  }

  /**
   * Update Tier 1 indexes (O(1) hash lookups)
   * Uses BatchWriteItem to reduce round-trips to DynamoDB
   * AR-120: Delegates to index-writers module
   */
  async updateTier1Indexes(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

    // Build index entries
    const indexEntries = this.buildTier1IndexEntries(
      deviceId,
      fingerprint,
      ttl,
    );

    if (indexEntries.length === 0) {
      return 0;
    }

    // Use BatchWriteItem for efficiency
    await batchWriteTier1Indexes(this.indexWriterDeps, indexEntries);
    return indexEntries.length;
  }

  /**
   * AR-120: Delegates to index-writers module
   */
  buildTier1IndexEntries(
    deviceId: string,
    fingerprint: Fingerprint,
    ttl: number,
  ): Tier1IndexEntry[] {
    return buildTier1IndexEntries(deviceId, fingerprint, ttl);
  }

  /**
   * AR-150: Update Tier 1 indexes with tier-gated identity association
   *
   * Hash indexes (stable#, fuzzy#) are always written.
   * Identity indexes (pubkey#, evercookie#, sigint#) are only written when
   * evidence_codes contains at least one code in ASSOCIATION_ALLOWED_EVIDENCE.
   *
   * This prevents viral spreading of device_ids from low-confidence Tier 2 matches.
   */
  async updateTier1IndexesWithEvidence(
    deviceId: string,
    fingerprint: Fingerprint,
    evidenceCodes?: string[],
  ): Promise<number> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

    // Always write hash indexes (stable#, fuzzy#)
    const hashEntries = buildHashIndexEntries(deviceId, fingerprint, ttl);

    // Only write identity indexes for high-confidence matches
    // Backward compat: if no evidence codes, write all indexes
    const shouldWriteIdentity =
      !evidenceCodes ||
      evidenceCodes.length === 0 ||
      evidenceCodes.some((code) => ASSOCIATION_ALLOWED_EVIDENCE.includes(code));

    const identityEntries = shouldWriteIdentity
      ? buildIdentityIndexEntries(deviceId, fingerprint, ttl)
      : [];

    const allEntries = [...hashEntries, ...identityEntries];

    if (allEntries.length === 0) {
      return 0;
    }

    await batchWriteTier1Indexes(this.indexWriterDeps, allEntries);
    return allEntries.length;
  }

  /**
   * Update Tier 2 buckets (compound filter matching)
   * Uses shorter TTL (7 days) to prevent bucket accumulation (AR-39)
   * Uses BatchWriteItem with retry logic for reliability (AR-40)
   * AR-56: Also increments cardinality counters for each bucket
   * AR-120: Delegates to index-writers module
   */
  async updateTier2Buckets(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    const ttlSeconds = this.deps.config.tier2BucketTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

    const bucketKeys = this.buildTier2BucketKeys(fingerprint);
    if (bucketKeys.length === 0) {
      return 0;
    }

    // Build bucket entries for batch write
    const bucketEntries = bucketKeys.map((bucketKey) => ({
      bucket_key: bucketKey,
      device_id: deviceId,
      ttl,
    }));

    // Use BatchWriteItem with retry logic
    await batchWriteTier2Buckets(this.indexWriterDeps, bucketEntries);

    // AR-56: Increment cardinality counters for each bucket
    await incrementBucketCardinalities(this.indexWriterDeps, bucketKeys, ttl);

    return bucketEntries.length;
  }

  /**
   * Build Tier 2 bucket keys for compound matching
   * AR-117: Delegates to shared bucket-keys helper
   * AR-120: Delegates to index-writers module
   */
  buildTier2BucketKeys(fingerprint: Fingerprint): string[] {
    return buildTier2BucketKeys(fingerprint);
  }

  /**
   * AR-82: Build session anchor bucket key for ephemeral short-window matching
   * AR-117: Delegates to shared bucket-keys helper
   * AR-120: Delegates to index-writers module
   */
  buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
    return buildSessionAnchorKey(fingerprint);
  }

  /**
   * AR-82: Update session anchor bucket for ephemeral matching
   * Stores created_at timestamp for application-side 10-minute validity check
   * Uses shorter TTL (1 hour) for DynamoDB cleanup
   * AR-120: Delegates to index-writers module
   */
  async updateSessionAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    const bucketKey = this.buildSessionAnchorKey(fingerprint);
    if (!bucketKey) {
      return false;
    }

    await writeSessionAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  /**
   * AR-94: Build IP+UA-only anchor bucket key for ephemeral matching
   * AR-117: Delegates to shared bucket-keys helper
   * AR-120: Delegates to index-writers module
   */
  buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
    return buildIpUaAnchorKey(fingerprint);
  }

  /**
   * AR-94: Update IP+UA-only anchor bucket for ephemeral matching
   * Stores created_at timestamp for application-side 3-minute validity check
   * Uses 1 hour TTL for DynamoDB cleanup (same as session anchor)
   * AR-120: Delegates to index-writers module
   */
  async updateIpUaAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    const bucketKey = this.buildIpUaAnchorKey(fingerprint);
    if (!bucketKey) {
      return false;
    }

    await writeIpUaAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  /**
   * Process a complete profile update (orchestration method)
   * Returns object indicating what was done
   */
  async processProfileUpdate(payload: ProfileUpdatePayload): Promise<{
    skipped: boolean;
    reason?: "mutation_gate" | "no_drift";
    tier1Writes?: number;
    tier2Writes?: number;
  }> {
    const {
      device_id,
      fingerprint,
      raw_fingerprint,
      timestamp,
      is_new_device = false,
      // AR-149/AR-150: Match context for tier-gated identity association
      evidence_codes,
    } = payload;

    // Atomically acquire mutation gate (AR-27: fixes TOCTOU race condition)
    // Gate is acquired upfront - if we crash after this, gate expires after TTL
    const acquired = await this.tryAcquireMutationGate(device_id);
    if (!acquired) {
      return { skipped: true, reason: "mutation_gate" };
    }

    // Load existing profile
    const existingProfile = await this.loadExistingProfile(device_id);

    // Check for drift
    const hasDrift =
      existingProfile !== null &&
      this.hasSignificantDrift(existingProfile, fingerprint);

    // AR-94: Always update anchor buckets (they're time-sensitive)
    // These must be refreshed on every request regardless of drift
    await this.updateSessionAnchorBucket(device_id, fingerprint);
    await this.updateIpUaAnchorBucket(device_id, fingerprint);

    if (existingProfile && !hasDrift) {
      // No significant drift - skip profile/tier writes but anchors were updated
      return { skipped: true, reason: "no_drift" };
    }

    // Perform updates (with flag computation)
    // AR-145: Pass raw_fingerprint for cross-field anomaly detection
    await this.updateProfile(
      device_id,
      fingerprint,
      timestamp,
      existingProfile,
      is_new_device,
      hasDrift,
      raw_fingerprint,
    );
    // AR-150: Use tier-gated identity association
    const tier1Writes = await this.updateTier1IndexesWithEvidence(
      device_id,
      fingerprint,
      evidence_codes,
    );
    const tier2Writes = await this.updateTier2Buckets(device_id, fingerprint);

    // Note: anchor buckets already updated above (before drift check)

    return {
      skipped: false,
      tier1Writes,
      tier2Writes,
    };
  }
}
