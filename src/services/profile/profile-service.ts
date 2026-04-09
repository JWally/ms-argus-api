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
import { updateIpHistory } from "./ip-history";
import {
  buildIdentityIndexEntries,
  batchWriteTier1Indexes,
  writeAnchorBucket,
  IndexWriterDeps,
  ASSOCIATION_ALLOWED_EVIDENCE,
} from "./index-writers";
import {
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "../../helpers/bucket-keys";

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
  sigint?: unknown;
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
}

/** Build the profile data record for DynamoDB, including IP history and timestamps. */
function buildProfileData(opts: {
  deviceId: string;
  fingerprint: Fingerprint;
  existingProfile: DeviceProfile | null;
  flags: string[];
  isNewDevice: boolean;
  now: number;
  ttl: number;
}): Record<string, unknown> {
  const {
    deviceId,
    fingerprint,
    existingProfile,
    flags,
    isNewDevice,
    now,
    ttl,
  } = opts;

  // Only update last_seen if hour changed (reduce write amplification)
  const currentHour = Math.floor(now / 3600000);
  const existingHour = existingProfile
    ? Math.floor(existingProfile.last_seen_at / 3600000)
    : 0;

  const existingHistory = existingProfile?.ip_history ?? [];
  const ipHistory =
    fingerprint.ip_address && fingerprint.asn !== undefined
      ? updateIpHistory(
          existingHistory,
          fingerprint.ip_address,
          fingerprint.asn,
          now,
        )
      : existingHistory;

  return {
    device_id: deviceId,
    ...fingerprint,
    first_seen_at: existingProfile?.first_seen_at ?? now,
    last_seen_at:
      currentHour !== existingHour
        ? now
        : (existingProfile?.last_seen_at ?? now),
    request_count: (existingProfile?.request_count ?? 0) + 1,
    updated_at: now,
    ttl,
    flags,
    risk_score: computeRiskScore(flags, existingProfile, isNewDevice),
    ip_history: ipHistory,
  };
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
   */
  tryAcquireMutationGate(deviceId: string): Promise<boolean> {
    return this.deps.cache.tryAcquireMutationGate(deviceId); // eslint-disable-line no-restricted-syntax
  }

  /**
   * Load existing device profile from DynamoDB
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
   */
  async updateProfile(params: UpdateProfileParams): Promise<void> {
    const {
      deviceId,
      fingerprint,
      existingProfile,
      isNewDevice = false,
      hasDrift = false,
      rawFingerprint,
      sigint,
    } = params;
    const now = Date.now();
    const ttl =
      Math.floor(now / 1000) + this.deps.config.profileTtlDays * 86400;

    const flags = computeFlags(fingerprint, existingProfile, {
      isNewDevice,
      hasDrift,
      raw: rawFingerprint,
      sigint,
    });

    const profileData = buildProfileData({
      deviceId,
      fingerprint,
      existingProfile,
      flags,
      isNewDevice,
      now,
      ttl,
    });

    await this.deps.dynamodb.send(
      new PutItemCommand({
        TableName: this.deps.config.profilesTable,
        Item: marshall(profileData, { removeUndefinedValues: true }),
      }),
    );
  }

  /**
   * Update identity indexes (pubkey#, evercookie#, sigint#) in DynamoDB tier1IndexTable.
   *
   * @returns Number of DynamoDB identity index entries written
   */
  async updateIdentityIndexes(
    deviceId: string,
    fingerprint: Fingerprint,
    evidenceCodes?: string[],
  ): Promise<number> {
    // Only write identity indexes for high-confidence matches
    const shouldWriteIdentity =
      !evidenceCodes ||
      evidenceCodes.length === 0 ||
      evidenceCodes.some((code) => ASSOCIATION_ALLOWED_EVIDENCE.includes(code));

    if (!shouldWriteIdentity) return 0;

    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;
    const identityEntries = buildIdentityIndexEntries(
      deviceId,
      fingerprint,
      ttl,
    );

    if (identityEntries.length === 0) return 0;

    await batchWriteTier1Indexes(this.indexWriterDeps, identityEntries);
    return identityEntries.length;
  }

  /**
   * Write an anchor bucket entry for ephemeral matching
   */
  private async writeAnchor(
    deviceId: string,
    bucketKey: string | null,
  ): Promise<boolean> {
    if (!bucketKey) return false;
    await writeAnchorBucket(this.indexWriterDeps, bucketKey, deviceId);
    return true;
  }

  async updateSessionAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    return this.writeAnchor(deviceId, buildSessionAnchorKey(fingerprint)); // eslint-disable-line no-restricted-syntax
  }

  async updateIpUaAnchorBucket(
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<boolean> {
    return this.writeAnchor(deviceId, buildIpUaAnchorKey(fingerprint)); // eslint-disable-line no-restricted-syntax
  }

  /**
   * Update anchor buckets (session anchor, IP+UA anchor)
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
   */
  async processProfileUpdate(
    payload: ProfileUpdatePayload,
  ): Promise<ProfileUpdateResult> {
    const {
      device_id,
      fingerprint,
      raw_fingerprint,
      sigint: payloadSigint,
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
      sigint: payloadSigint,
    });

    const tier1Writes = await this.updateIdentityIndexes(
      device_id,
      fingerprint,
      evidence_codes,
    );

    return {
      skipped: false,
      tier1Writes,
    };
  }
}
