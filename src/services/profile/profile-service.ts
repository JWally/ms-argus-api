import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { DynamoCacheService } from "../cache";
import { Fingerprint, ProfileUpdatePayload, DeviceProfile } from "./types";
import { hasSignificantDrift } from "./drift-detection";
import { computeFlags, computeRiskScore } from "./flag-computation";
import {
  buildIdentityIndexEntries,
  buildHashIndexEntries,
  batchWriteTier1Indexes,
  writeAnchorBucket,
  buildSimHashBandEntries,
  batchWriteSimHashBands,
  IndexWriterDeps,
  ASSOCIATION_ALLOWED_EVIDENCE,
} from "./index-writers";
import {
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
  simhashBandWrites?: number;
}

/**
 * Profile service handles device profile updates
 * Implements mutation gating to reduce unnecessary writes
 */
export class ProfileService {
  private indexWriterDeps: IndexWriterDeps;

  constructor(private deps: ProfileServiceDeps) {
    this.indexWriterDeps = {
      dynamodb: deps.dynamodb,
      tier1IndexTable: deps.config.tier1IndexTable,
      tier2BucketsTable: deps.config.tier2BucketsTable,
    };
  }

  /**
   * Atomically try to acquire the mutation gate for a device
   * Uses DynamoDB conditional write to avoid TOCTOU race condition
   * @param deviceId - The device ID to acquire the gate for
   * @returns True if gate was acquired (we should update), false if already held
   */
  tryAcquireMutationGate(deviceId: string): Promise<boolean> {
    return this.deps.cache.tryAcquireMutationGate(deviceId);
  }

  /**
   * Load existing device profile from DynamoDB
   * @param deviceId - The device ID to load
   * @returns Device profile if found, null otherwise
   */
  async loadExistingProfile(deviceId: string): Promise<DeviceProfile | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.profilesTable,
        Key: { device_id: { S: deviceId } },
      }),
    );
    return result.Item ? (unmarshall(result.Item) as DeviceProfile) : null;
  }

  /**
   * Update device profile in DynamoDB
   * Computes flags, risk score, and manages last_seen timestamps
   * @param params - Profile update parameters including device ID, fingerprint, and context
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

    const flags = computeFlags(fingerprint, existingProfile, {
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
      risk_score: computeRiskScore(flags, existingProfile, isNewDevice),
    };

    await this.deps.dynamodb.send(
      new PutItemCommand({
        TableName: this.deps.config.profilesTable,
        Item: marshall(profileData, { removeUndefinedValues: true }),
      }),
    );
  }

  /**
   * Update Tier 1 indexes with tier-gated identity association
   *
   * Hash indexes (stable#, fuzzy#) are always written.
   * Identity indexes (pubkey#, evercookie#, sigint#) are only written when
   * evidence_codes contains at least one code in ASSOCIATION_ALLOWED_EVIDENCE.
   *
   * This prevents viral spreading of device_ids from low-confidence Tier 2 matches.
   * @param deviceId - The device ID to index
   * @param fingerprint - The fingerprint containing hash and identity values
   * @param evidenceCodes - Evidence codes from the match (determines if identity indexes are written)
   * @returns Number of index entries written
   */
  async updateTier1IndexesWithEvidence(
    deviceId: string,
    fingerprint: Fingerprint,
    evidenceCodes?: string[],
  ): Promise<number> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

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
   * Write an anchor bucket entry for ephemeral matching
   * @param deviceId - The device ID to anchor
   * @param bucketKey - The bucket key, or null if signals are missing
   * @returns True if written, false if skipped (null bucket key)
   */
  private async writeAnchor(
    deviceId: string,
    bucketKey: string | null,
  ): Promise<boolean> {
    if (!bucketKey) return false;
    await writeAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  /**
   * Update session anchor bucket for short-lived matching
   * @param deviceId - The device ID to anchor
   * @param fingerprint - The fingerprint containing anchor signals
   * @returns True if anchor was written, false if required signals missing
   */
  async updateSessionAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    return this.writeAnchor(deviceId, buildSessionAnchorKey(fingerprint));
  }

  /**
   * Update IP+UserAgent anchor bucket for very short-lived matching
   * @param deviceId - The device ID to anchor
   * @param fingerprint - The fingerprint containing IP and user agent
   * @returns True if anchor was written, false if required signals missing
   */
  async updateIpUaAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    return this.writeAnchor(deviceId, buildIpUaAnchorKey(fingerprint));
  }

  /**
   * Update SimHash LSH band entries for Tier 1.5 matching
   * Only writes if SimHash tier is enabled via feature flag
   * @param deviceId - The device ID to index
   * @param fingerprint - The fingerprint containing fuzzy_hash
   * @returns Number of band entries written (0 if disabled or no hash)
   */
  async updateSimHashBands(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
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

  /**
   * Update anchor buckets (session anchor, IP+UA anchor)
   * @param deviceId - The device ID to add to buckets
   * @param fingerprint - The fingerprint containing bucket signals
   */
  private async updateAnchorBuckets(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<void> {
    await this.updateSessionAnchorBucket(deviceId, fingerprint);
    await this.updateIpUaAnchorBucket(deviceId, fingerprint);
  }

  /**
   * Process a complete profile update (orchestration method)
   * Handles mutation gating, drift detection, and all index updates
   * @param payload - Profile update payload with device ID, fingerprint, and context
   * @returns Result indicating what was done (skipped/written counts)
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
      hasSignificantDrift(existingProfile, fingerprint);

    // Anchors are always refreshed regardless of drift
    await this.updateAnchorBuckets(device_id, fingerprint);

    if (existingProfile && !hasDrift) {
      return { skipped: true, reason: "no_drift" };
    }

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
      simhashBandWrites,
    };
  }
}
