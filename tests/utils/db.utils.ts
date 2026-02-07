// tests/utils/db.utils.ts

import {
  DynamoDBClient,
  PutItemCommand,
  DeleteItemCommand,
  QueryCommand,
  BatchWriteItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { Fingerprint } from "../../src/types/fingerprint";
import { createFingerprint, FingerprintPresets } from "./fingerprint.factory";

const TENANT_KEY_CONDITION = "tenant_id = :tid";

/**
 * Test database configuration
 */
export interface TestDbConfig {
  profilesTable: string;
  tier1IndexTable: string;
  tier2BucketsTable: string;
  sessionCacheTable: string;
  region?: string;
}

/**
 * Default configuration for dev environment
 */
export const DEFAULT_TEST_DB_CONFIG: TestDbConfig = {
  profilesTable: process.env.PROFILES_TABLE || "ms-argus-api-dev-jw-profiles",
  tier1IndexTable:
    process.env.TIER1_INDEX_TABLE || "ms-argus-api-dev-jw-tier1-index",
  tier2BucketsTable:
    process.env.TIER2_BUCKETS_TABLE || "ms-argus-api-dev-jw-tier2-buckets-v2",
  sessionCacheTable:
    process.env.SESSION_CACHE_TABLE || "ms-argus-api-dev-jw-session-cache",
  region: process.env.AWS_REGION || "us-east-1",
};

/**
 * Device profile for seeding
 */
export interface SeedDeviceProfile {
  tenantId: string;
  deviceId: string;
  fingerprint: Fingerprint;
  riskScore?: number;
  flags?: string[];
  requestCount?: number;
}

/**
 * Test database client wrapper
 */
export class TestDbClient {
  private client: DynamoDBClient;
  private config: TestDbConfig;

  constructor(config: TestDbConfig = DEFAULT_TEST_DB_CONFIG) {
    this.config = config;
    this.client = new DynamoDBClient({ region: config.region });
  }

  /**
   * Seed a device profile with all associated indexes
   */
  async seedDevice(profile: SeedDeviceProfile): Promise<void> {
    const now = Date.now();
    const ttl = Math.floor(now / 1000) + 60 * 24 * 60 * 60; // 60 days
    const tier2Ttl = Math.floor(now / 1000) + 7 * 24 * 60 * 60; // 7 days

    await this.writeProfile(profile, now, ttl);
    await this.writeTier1Indexes(profile, ttl);
    await this.writeTier2Buckets(profile, tier2Ttl);
  }

  private async writeProfile(
    profile: SeedDeviceProfile,
    now: number,
    ttl: number,
  ): Promise<void> {
    await this.client.send(
      new PutItemCommand({
        TableName: this.config.profilesTable,
        Item: marshall({
          tenant_id: profile.tenantId,
          device_id: profile.deviceId,
          stable_hash: profile.fingerprint.stable_hash,
          fuzzy_hash: profile.fingerprint.fuzzy_hash,
          canvas_hash: profile.fingerprint.canvas_hash,
          audio_hash: profile.fingerprint.audio_hash,
          risk_score: profile.riskScore ?? 0.3,
          flags: profile.flags ?? [],
          request_count: profile.requestCount ?? 1,
          first_seen_at: now,
          last_seen_at: now,
          updated_at: now,
          ttl,
        }),
      }),
    );
  }

  private async writeTier1Indexes(
    profile: SeedDeviceProfile,
    ttl: number,
  ): Promise<void> {
    const entries: { prefix: string; value: string | undefined }[] = [
      { prefix: "evercookie", value: profile.fingerprint.evercookie_id },
      { prefix: "stable", value: profile.fingerprint.stable_hash },
      { prefix: "fuzzy", value: profile.fingerprint.fuzzy_hash },
    ];

    const writes = entries
      .filter((e) => e.value)
      .map((e) =>
        this.client.send(
          new PutItemCommand({
            TableName: this.config.tier1IndexTable,
            Item: marshall({
              tenant_id: profile.tenantId,
              hash_key: `${e.prefix}#${e.value}`,
              device_id: profile.deviceId,
              risk_score: profile.riskScore ?? 0.3,
              flags: profile.flags ?? [],
              ttl,
            }),
          }),
        ),
      );

    await Promise.all(writes);
  }

  private async writeTier2Buckets(
    profile: SeedDeviceProfile,
    tier2Ttl: number,
  ): Promise<void> {
    const fp = profile.fingerprint;
    const bucketKeys: string[] = [];

    if (fp.ip_address && fp.ja4) {
      bucketKeys.push(`${profile.tenantId}#ip_ja4#${fp.ip_address}#${fp.ja4}`);
    }
    if (fp.gpu_renderer && fp.screen_dims && fp.timezone) {
      bucketKeys.push(
        `${profile.tenantId}#gpu_screen_tz#${fp.gpu_renderer}#${fp.screen_dims}#${fp.timezone}`,
      );
    }
    if (fp.audio_hash && fp.canvas_hash) {
      bucketKeys.push(
        `${profile.tenantId}#audio_canvas#${fp.audio_hash}#${fp.canvas_hash}`,
      );
    }

    const writes = bucketKeys.map((bucketKey) =>
      this.client.send(
        new PutItemCommand({
          TableName: this.config.tier2BucketsTable,
          Item: marshall({
            bucket_key: bucketKey,
            device_id: profile.deviceId,
            ttl: tier2Ttl,
          }),
        }),
      ),
    );

    await Promise.all(writes);
  }

  /**
   * Seed multiple devices
   */
  async seedDevices(profiles: SeedDeviceProfile[]): Promise<void> {
    await Promise.all(profiles.map((p) => this.seedDevice(p)));
  }

  /**
   * Delete a device and all associated indexes
   */
  async deleteDevice(tenantId: string, deviceId: string): Promise<void> {
    await this.deleteTier1IndexesForDevice(tenantId, deviceId);

    await this.client.send(
      new DeleteItemCommand({
        TableName: this.config.profilesTable,
        Key: marshall({ tenant_id: tenantId, device_id: deviceId }),
      }),
    );
  }

  private async deleteTier1IndexesForDevice(
    tenantId: string,
    deviceId: string,
  ): Promise<void> {
    const profileResult = await this.client.send(
      new QueryCommand({
        TableName: this.config.profilesTable,
        KeyConditionExpression: "tenant_id = :tid AND device_id = :did",
        ExpressionAttributeValues: {
          ":tid": { S: tenantId },
          ":did": { S: deviceId },
        },
      }),
    );

    if (!profileResult.Items || profileResult.Items.length === 0) return;

    const profile = unmarshall(profileResult.Items[0]);
    const hashKeys = [
      profile.stable_hash ? `stable#${profile.stable_hash}` : null,
      profile.fuzzy_hash ? `fuzzy#${profile.fuzzy_hash}` : null,
    ].filter(Boolean) as string[];

    await Promise.all(
      hashKeys.map((hashKey) =>
        this.client.send(
          new DeleteItemCommand({
            TableName: this.config.tier1IndexTable,
            Key: marshall({ tenant_id: tenantId, hash_key: hashKey }),
          }),
        ),
      ),
    );
  }

  /**
   * Cleanup all data for a tenant
   * WARNING: Use only for test tenants!
   */
  async cleanupTenant(
    tenantId: string,
  ): Promise<{ profilesDeleted: number; indexesDeleted: number }> {
    const profilesDeleted = await this.batchDeleteByTenant(
      tenantId,
      this.config.profilesTable,
      "tenant_id, device_id",
    );
    const indexesDeleted = await this.batchDeleteByTenant(
      tenantId,
      this.config.tier1IndexTable,
      "tenant_id, hash_key",
    );
    return { profilesDeleted, indexesDeleted };
  }

  private async batchDeleteByTenant(
    tenantId: string,
    tableName: string,
    projectionExpression: string,
  ): Promise<number> {
    let deleted = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
      const result = await this.client.send(
        new QueryCommand({
          TableName: tableName,
          KeyConditionExpression: TENANT_KEY_CONDITION,
          ExpressionAttributeValues: { ":tid": { S: tenantId } },
          ProjectionExpression: projectionExpression,
          ExclusiveStartKey: lastEvaluatedKey as Record<string, { S: string }>,
        }),
      );

      if (result.Items && result.Items.length > 0) {
        const batches = [];
        for (let i = 0; i < result.Items.length; i += 25) {
          batches.push(
            this.client.send(
              new BatchWriteItemCommand({
                RequestItems: {
                  [tableName]: result.Items.slice(i, i + 25).map((item) => ({
                    DeleteRequest: { Key: item },
                  })),
                },
              }),
            ),
          );
        }
        await Promise.all(batches);
        deleted += result.Items.length;
      }

      lastEvaluatedKey = result.LastEvaluatedKey as
        | Record<string, unknown>
        | undefined;
    } while (lastEvaluatedKey);

    return deleted;
  }

  /**
   * Get a profile by device ID
   */
  async getProfile(
    tenantId: string,
    deviceId: string,
  ): Promise<Record<string, unknown> | null> {
    const result = await this.client.send(
      new QueryCommand({
        TableName: this.config.profilesTable,
        KeyConditionExpression: "tenant_id = :tid AND device_id = :did",
        ExpressionAttributeValues: {
          ":tid": { S: tenantId },
          ":did": { S: deviceId },
        },
      }),
    );

    if (result.Items && result.Items.length > 0) {
      return unmarshall(result.Items[0]);
    }
    return null;
  }

  /**
   * Count profiles for a tenant
   */
  async countProfiles(tenantId: string): Promise<number> {
    const result = await this.client.send(
      new QueryCommand({
        TableName: this.config.profilesTable,
        KeyConditionExpression: TENANT_KEY_CONDITION,
        ExpressionAttributeValues: {
          ":tid": { S: tenantId },
        },
        Select: "COUNT",
      }),
    );
    return result.Count ?? 0;
  }
}

/**
 * Pre-defined test scenarios for seeding
 */
export const TestScenarios = {
  /**
   * Single returning user with consistent fingerprint
   */
  RETURNING_USER: (
    tenantId: string,
    deviceId: string = `dev_returning_${Date.now()}`,
  ) => ({
    tenantId,
    deviceId,
    fingerprint: createFingerprint(FingerprintPresets.FULL),
    riskScore: 0.2,
    flags: [],
    requestCount: 10,
  }),

  /**
   * Bot-like device with suspicious signals
   */
  BOT_DEVICE: (
    tenantId: string,
    deviceId: string = `dev_bot_${Date.now()}`,
  ) => ({
    tenantId,
    deviceId,
    fingerprint: createFingerprint(FingerprintPresets.BOT_LIKE),
    riskScore: 0.8,
    flags: ["bot_detected", "headless_browser"],
    requestCount: 1000,
  }),

  /**
   * High-risk device with multiple flags
   */
  HIGH_RISK_DEVICE: (
    tenantId: string,
    deviceId: string = `dev_highrisk_${Date.now()}`,
  ) => ({
    tenantId,
    deviceId,
    fingerprint: createFingerprint(FingerprintPresets.FULL),
    riskScore: 0.9,
    flags: ["fraud_history", "multiple_accounts", "velocity_exceeded"],
    requestCount: 50,
  }),

  /**
   * Mobile device
   */
  MOBILE_DEVICE: (
    tenantId: string,
    deviceId: string = `dev_mobile_${Date.now()}`,
  ) => ({
    tenantId,
    deviceId,
    fingerprint: createFingerprint(FingerprintPresets.MOBILE),
    riskScore: 0.3,
    flags: [],
    requestCount: 5,
  }),
};

/**
 * Seed a predefined scenario
 */
export async function seedScenario(
  scenario: keyof typeof TestScenarios,
  tenantId: string,
  config?: TestDbConfig,
): Promise<SeedDeviceProfile> {
  const client = new TestDbClient(config);
  const profile = TestScenarios[scenario](tenantId);
  await client.seedDevice(profile);
  return profile;
}

/**
 * Cleanup a tenant (convenience function)
 */
export async function cleanupTenant(
  tenantId: string,
  config?: TestDbConfig,
): Promise<{ profilesDeleted: number; indexesDeleted: number }> {
  const client = new TestDbClient(config);
  return client.cleanupTenant(tenantId);
}
