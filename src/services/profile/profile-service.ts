// src/services/profile/profile-service.ts
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
  batchWriteTier2Buckets,
  incrementBucketCardinalities,
  writeAnchorBucket,
  buildSimHashBandEntries,
  batchWriteSimHashBands,
  Tier1IndexEntry,
  IndexWriterDeps,
  ASSOCIATION_ALLOWED_EVIDENCE,
} from "./index-writers";
import {
  buildBucketKeys,
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "../../helpers/bucket-keys";
import { getSimHashFlags } from "../../helpers/constants";

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
 * Parameters for updateProfile method
 */
export interface UpdateProfileParams {
  deviceId: string;
  fingerprint: Fingerprint;
  timestamp: number;
  existingProfile: DeviceProfile | null;
  isNewDevice?: boolean;
  hasDrift?: boolean;
  rawFingerprint?: unknown;
}

/**
 * Dependencies injected into the profile service
 */
export interface ProfileServiceDeps {
  dynamodb: DynamoDBClient;
  cache: DynamoCacheService;
  config: ProfileServiceConfig;
}

interface ProfileUpdateResult {
  skipped: boolean;
  reason?: "mutation_gate" | "no_drift";
  tier1Writes?: number;
  tier2Writes?: number;
  simhashBandWrites?: number;
}

/**
 * Profile service handles device profile updates
 * Implements mutation gating to reduce unnecessary writes
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
   * Uses DynamoDB conditional write to avoid TOCTOU race condition
   * Returns true if gate was acquired (we should update), false if already held
   */
  tryAcquireMutationGate(deviceId: string): Promise<boolean> {
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

  hasSignificantDrift(existing: DeviceProfile, incoming: Fingerprint): boolean {
    return hasSignificantDrift(existing, incoming);
  }

  detectBotSignals(fingerprint: Fingerprint): string[] {
    return detectBotSignals(fingerprint);
  }

  computeFlags(
    fingerprint: Fingerprint,
    existingProfile: DeviceProfile | null,
    ctx: { isNewDevice: boolean; hasDrift: boolean; raw?: unknown },
  ): string[] {
    return computeFlags(fingerprint, existingProfile, ctx);
  }

  computeRiskScore(
    flags: string[],
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean,
  ): number {
    return computeRiskScore(flags, existingProfile, isNewDevice);
  }

  /**
   * Update device profile in DynamoDB
   */
  async updateProfile(params: UpdateProfileParams): Promise<void> {
    const {
      deviceId,
      fingerprint,
      existingProfile,
      isNewDevice = false,
      hasDrift = false,
      rawFingerprint,
    } = params;
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
    const flags = this.computeFlags(fingerprint, existingProfile, {
      isNewDevice,
      hasDrift,
      raw: rawFingerprint,
    });

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

  buildTier1IndexEntries(
    deviceId: string,
    fingerprint: Fingerprint,
    ttl: number,
  ): Tier1IndexEntry[] {
    return buildTier1IndexEntries(deviceId, fingerprint, ttl);
  }

  /**
   * Update Tier 1 indexes with tier-gated identity association
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
   * Uses shorter TTL (7 days) to prevent bucket accumulation
   * Also increments cardinality counters for each bucket
   */
  async updateTier2Buckets(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    const ttlSeconds = this.deps.config.tier2BucketTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

    const bucketKeys = buildBucketKeys(fingerprint);
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

    // Increment cardinality counters for each bucket
    await incrementBucketCardinalities(this.indexWriterDeps, bucketKeys, ttl);

    return bucketEntries.length;
  }

  async updateSessionAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    const bucketKey = buildSessionAnchorKey(fingerprint);
    if (!bucketKey) {
      return false;
    }

    await writeAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  async updateIpUaAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    const bucketKey = buildIpUaAnchorKey(fingerprint);
    if (!bucketKey) {
      return false;
    }

    await writeAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  /**
   * Update SimHash LSH band entries for Tier 1.5 matching
   * Only writes if SimHash tier is enabled via feature flag
   */
  async updateSimHashBands(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    // Check if SimHash is enabled before writing bands
    const flags = getSimHashFlags();
    if (!flags.ENABLED) {
      return 0;
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const bandEntries = buildSimHashBandEntries(
      deviceId,
      fingerprint,
      timestamp,
    );

    if (bandEntries.length === 0) {
      return 0;
    }

    await batchWriteSimHashBands(this.indexWriterDeps, bandEntries);
    return bandEntries.length;
  }

  private async updateBuckets(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    await this.updateSessionAnchorBucket(deviceId, fingerprint);
    await this.updateIpUaAnchorBucket(deviceId, fingerprint);
    return this.updateTier2Buckets(deviceId, fingerprint);
  }

  /**
   * Process a complete profile update (orchestration method)
   * Returns object indicating what was done
   */
  async processProfileUpdate(
    payload: ProfileUpdatePayload,
  ): Promise<ProfileUpdateResult> {
    const {
      device_id,
      fingerprint,
      raw_fingerprint,
      timestamp,
      is_new_device = false,
      evidence_codes,
    } = payload;

    const acquired = await this.tryAcquireMutationGate(device_id);
    if (!acquired) {
      return { skipped: true, reason: "mutation_gate" };
    }

    const existingProfile = await this.loadExistingProfile(device_id);
    const hasDrift =
      existingProfile !== null &&
      this.hasSignificantDrift(existingProfile, fingerprint);

    // Anchors + tier2 are always refreshed regardless of drift
    const tier2Writes = await this.updateBuckets(device_id, fingerprint);

    if (existingProfile && !hasDrift) {
      // No significant drift - skip profile/tier1/simhash writes
      return { skipped: true, reason: "no_drift", tier2Writes };
    }

    // Perform updates (with flag computation)
    await this.updateProfile({
      deviceId: device_id,
      fingerprint,
      timestamp,
      existingProfile,
      isNewDevice: is_new_device,
      hasDrift,
      rawFingerprint: raw_fingerprint,
    });
    const tier1Writes = await this.updateTier1IndexesWithEvidence(
      device_id,
      fingerprint,
      evidence_codes,
    );

    const simhashBandWrites = await this.updateSimHashBands(
      device_id,
      fingerprint,
    );

    return {
      skipped: false,
      tier1Writes,
      tier2Writes,
      simhashBandWrites,
    };
  }
}
