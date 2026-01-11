// src/services/profile/profile-service.ts
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import type { Redis } from "ioredis";
import {
  Fingerprint,
  ProfileUpdatePayload,
  DeviceProfile,
  DeviceFlags,
} from "./types";

/**
 * Thresholds for flag computation
 */
const FLAG_THRESHOLDS = {
  /** Requests per hour that triggers RAPID_REQUESTS flag */
  RAPID_REQUESTS_PER_HOUR: 50,
} as const;

/**
 * Configuration for the profile service
 */
export interface ProfileServiceConfig {
  profilesTable: string;
  tier1IndexTable: string;
  tier2BucketsTable: string;
  profileTtlDays: number;
  mutationGateTtlSeconds: number;
}

/**
 * Dependencies injected into the profile service
 */
export interface ProfileServiceDeps {
  dynamodb: DynamoDBClient;
  redis: Redis;
  config: ProfileServiceConfig;
}

/**
 * Profile service handles device profile updates
 * Implements mutation gating to reduce unnecessary writes
 */
export class ProfileService {
  constructor(private deps: ProfileServiceDeps) {}

  /**
   * Check if device was recently updated (mutation gate)
   * Returns true if we should update, false if we should skip
   */
  async checkMutationGate(deviceId: string): Promise<boolean> {
    const key = `recently_updated:${deviceId}`;
    const exists = await this.deps.redis.exists(key);
    return exists === 0; // Update if key doesn't exist
  }

  /**
   * Set mutation gate to prevent rapid repeated updates
   */
  async setMutationGate(deviceId: string): Promise<void> {
    const key = `recently_updated:${deviceId}`;
    await this.deps.redis.setex(
      key,
      this.deps.config.mutationGateTtlSeconds,
      "1",
    );
  }

  /**
   * Load existing device profile from DynamoDB
   */
  async loadExistingProfile(
    tenantId: string,
    deviceId: string,
  ): Promise<DeviceProfile | null> {
    const result = await this.deps.dynamodb.send(
      new GetItemCommand({
        TableName: this.deps.config.profilesTable,
        Key: {
          tenant_id: { S: tenantId },
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
   * Check if incoming fingerprint has significant drift from existing profile
   * Returns true if we should update, false if fingerprint is essentially the same
   */
  hasSignificantDrift(existing: DeviceProfile, incoming: Fingerprint): boolean {
    // Major drift: stable hash changed
    if (existing.stable_hash !== incoming.stable_hash) {
      return true;
    }

    // Count how many signals have changed
    let changedSignals = 0;

    if (existing.canvas_hash !== incoming.canvas_hash) changedSignals++;
    if (existing.webgl_hash !== incoming.webgl_hash) changedSignals++;
    if (existing.audio_hash !== incoming.audio_hash) changedSignals++;
    if (existing.gpu_renderer !== incoming.gpu_renderer) changedSignals++;
    if (existing.screen_dims !== incoming.screen_dims) changedSignals++;

    // Drift threshold: 2+ signals changed
    return changedSignals >= 2;
  }

  /**
   * Detect bot-like signals in fingerprint
   * Returns array of detected bot flags
   */
  detectBotSignals(fingerprint: Fingerprint): string[] {
    const flags: string[] = [];

    // SwiftShader is a software renderer commonly used by headless browsers
    if (fingerprint.gpu_renderer?.toLowerCase().includes("swiftshader")) {
      flags.push(DeviceFlags.HEADLESS_BROWSER);
      flags.push(DeviceFlags.BOT_DETECTED);
    }

    // Very small viewport (800x600) is typical of automated browsers
    if (fingerprint.screen_dims === "800x600") {
      flags.push(DeviceFlags.BOT_DETECTED);
    }

    // Check user agent for bot patterns
    if (fingerprint.user_agent) {
      const ua = fingerprint.user_agent.toLowerCase();
      if (
        ua.includes("bot") ||
        ua.includes("crawler") ||
        ua.includes("spider") ||
        ua.includes("headless")
      ) {
        flags.push(DeviceFlags.BOT_DETECTED);
      }
    }

    // Single CPU core and very low memory are atypical for real devices
    if (
      fingerprint.hardware_concurrency === 1 &&
      fingerprint.device_memory !== undefined &&
      fingerprint.device_memory < 1
    ) {
      flags.push(DeviceFlags.BOT_DETECTED);
    }

    // Remove duplicates
    return [...new Set(flags)];
  }

  /**
   * Compute all flags for a profile based on fingerprint and profile state
   */
  computeFlags(
    fingerprint: Fingerprint,
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean,
    hasDrift: boolean,
  ): string[] {
    const flags: string[] = [];

    // NEW_DEVICE flag for first-time devices
    if (isNewDevice) {
      flags.push(DeviceFlags.NEW_DEVICE);
    }

    // Bot detection flags
    const botFlags = this.detectBotSignals(fingerprint);
    flags.push(...botFlags);

    // FINGERPRINT_MISMATCH flag when significant drift is detected
    if (existingProfile && hasDrift) {
      flags.push(DeviceFlags.FINGERPRINT_MISMATCH);
    }

    // RAPID_REQUESTS flag - check if request rate is suspicious
    if (existingProfile) {
      const hoursSinceFirstSeen =
        (Date.now() - existingProfile.first_seen_at) / (1000 * 60 * 60);
      const requestsPerHour =
        hoursSinceFirstSeen > 0
          ? (existingProfile.request_count + 1) / hoursSinceFirstSeen
          : existingProfile.request_count + 1;

      if (requestsPerHour > FLAG_THRESHOLDS.RAPID_REQUESTS_PER_HOUR) {
        flags.push(DeviceFlags.RAPID_REQUESTS);
      }
    }

    // Preserve existing positive flags (VERIFIED, RETURNING_USER)
    if (existingProfile?.flags) {
      const positiveFlags = existingProfile.flags.filter(
        (f) => f === DeviceFlags.VERIFIED || f === DeviceFlags.RETURNING_USER,
      );
      flags.push(...positiveFlags);
    }

    // Remove duplicates and return
    return [...new Set(flags)];
  }

  /**
   * Update device profile in DynamoDB
   */
  async updateProfile(
    tenantId: string,
    deviceId: string,
    fingerprint: Fingerprint,
    timestamp: number,
    existingProfile: DeviceProfile | null,
    isNewDevice: boolean = false,
    hasDrift: boolean = false,
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
    const flags = this.computeFlags(
      fingerprint,
      existingProfile,
      isNewDevice,
      hasDrift,
    );

    const profileData: Record<string, unknown> = {
      tenant_id: tenantId,
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

    // Preserve existing risk score or set neutral for new profiles
    // (AR-17 will implement dynamic risk score calculation)
    profileData.risk_score = existingProfile?.risk_score ?? 0.5;

    await this.deps.dynamodb.send(
      new PutItemCommand({
        TableName: this.deps.config.profilesTable,
        Item: marshall(profileData, { removeUndefinedValues: true }),
      }),
    );
  }

  /**
   * Update Tier 1 indexes (O(1) hash lookups)
   */
  async updateTier1Indexes(
    tenantId: string,
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;
    const writes: Promise<unknown>[] = [];

    // Build index entries
    const indexEntries = this.buildTier1IndexEntries(
      tenantId,
      deviceId,
      fingerprint,
      ttl,
    );

    for (const entry of indexEntries) {
      writes.push(
        this.deps.dynamodb.send(
          new PutItemCommand({
            TableName: this.deps.config.tier1IndexTable,
            Item: marshall(entry),
          }),
        ),
      );
    }

    await Promise.all(writes);
    return writes.length;
  }

  /**
   * Build Tier 1 index entries for a fingerprint
   */
  buildTier1IndexEntries(
    tenantId: string,
    deviceId: string,
    fingerprint: Fingerprint,
    ttl: number,
  ): Array<{
    tenant_id: string;
    hash_key: string;
    device_id: string;
    ttl: number;
  }> {
    const entries: Array<{
      tenant_id: string;
      hash_key: string;
      device_id: string;
      ttl: number;
    }> = [];

    if (fingerprint.evercookie_id) {
      entries.push({
        tenant_id: tenantId,
        hash_key: `evercookie#${fingerprint.evercookie_id}`,
        device_id: deviceId,
        ttl,
      });
    }

    if (fingerprint.stable_hash) {
      entries.push({
        tenant_id: tenantId,
        hash_key: `stable#${fingerprint.stable_hash}`,
        device_id: deviceId,
        ttl,
      });
    }

    if (fingerprint.fuzzy_hash) {
      entries.push({
        tenant_id: tenantId,
        hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
        device_id: deviceId,
        ttl,
      });
    }

    if (fingerprint.ja4) {
      entries.push({
        tenant_id: tenantId,
        hash_key: `ja4#${fingerprint.ja4}`,
        device_id: deviceId,
        ttl,
      });
    }

    return entries;
  }

  /**
   * Update Tier 2 buckets (compound filter matching)
   */
  async updateTier2Buckets(
    tenantId: string,
    deviceId: string,
    fingerprint: Fingerprint,
  ): Promise<number> {
    const ttlSeconds = this.deps.config.profileTtlDays * 24 * 60 * 60;
    const ttl = Math.floor(Date.now() / 1000) + ttlSeconds;

    const bucketKeys = this.buildTier2BucketKeys(tenantId, fingerprint);
    const updates: Promise<unknown>[] = [];

    for (const bucketKey of bucketKeys) {
      updates.push(this.addDeviceToBucket(bucketKey, deviceId, ttl));
    }

    await Promise.all(updates);
    return updates.length;
  }

  /**
   * Build Tier 2 bucket keys for compound matching
   */
  buildTier2BucketKeys(tenantId: string, fingerprint: Fingerprint): string[] {
    const keys: string[] = [];

    // IP + JA4 bucket
    if (fingerprint.ip_address && fingerprint.ja4) {
      keys.push(
        `${tenantId}#ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`,
      );
    }

    // GPU + Screen + Timezone bucket
    if (
      fingerprint.gpu_renderer &&
      fingerprint.screen_dims &&
      fingerprint.timezone
    ) {
      keys.push(
        `${tenantId}#gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`,
      );
    }

    // Audio + Canvas bucket
    if (fingerprint.audio_hash && fingerprint.canvas_hash) {
      keys.push(
        `${tenantId}#audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`,
      );
    }

    return keys;
  }

  /**
   * Add device to a Tier 2 bucket using adjacency list pattern
   * Each device is a separate item with (bucket_key, device_id) composite key
   * This avoids the 400KB item size limit of String Sets
   */
  private async addDeviceToBucket(
    bucketKey: string,
    deviceId: string,
    ttl: number,
  ): Promise<void> {
    await this.deps.dynamodb.send(
      new PutItemCommand({
        TableName: this.deps.config.tier2BucketsTable,
        Item: {
          bucket_key: { S: bucketKey },
          device_id: { S: deviceId },
          ttl: { N: String(ttl) },
        },
      }),
    );
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
      tenant_id,
      device_id,
      fingerprint,
      timestamp,
      is_new_device = false,
    } = payload;

    // Check mutation gate
    const shouldUpdate = await this.checkMutationGate(device_id);
    if (!shouldUpdate) {
      return { skipped: true, reason: "mutation_gate" };
    }

    // Load existing profile
    const existingProfile = await this.loadExistingProfile(
      tenant_id,
      device_id,
    );

    // Check for drift
    const hasDrift =
      existingProfile !== null &&
      this.hasSignificantDrift(existingProfile, fingerprint);

    if (existingProfile && !hasDrift) {
      // No significant drift - just update mutation gate and skip
      await this.setMutationGate(device_id);
      return { skipped: true, reason: "no_drift" };
    }

    // Perform updates (with flag computation)
    await this.updateProfile(
      tenant_id,
      device_id,
      fingerprint,
      timestamp,
      existingProfile,
      is_new_device,
      hasDrift,
    );
    const tier1Writes = await this.updateTier1Indexes(
      tenant_id,
      device_id,
      fingerprint,
    );
    const tier2Writes = await this.updateTier2Buckets(
      tenant_id,
      device_id,
      fingerprint,
    );

    // Set mutation gate
    await this.setMutationGate(device_id);

    return {
      skipped: false,
      tier1Writes,
      tier2Writes,
    };
  }
}
