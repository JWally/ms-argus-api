// tests/utils/db.utils.ts
// AR-60: Database utilities for test setup and teardown

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

    // 1. Write profile
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

    // 2. Write Tier 1 indexes
    const tier1Writes: Promise<unknown>[] = [];

    if (profile.fingerprint.evercookie_id) {
      tier1Writes.push(
        this.client.send(
          new PutItemCommand({
            TableName: this.config.tier1IndexTable,
            Item: marshall({
              tenant_id: profile.tenantId,
              hash_key: `evercookie#${profile.fingerprint.evercookie_id}`,
              device_id: profile.deviceId,
              risk_score: profile.riskScore ?? 0.3,
              flags: profile.flags ?? [],
              ttl,
            }),
          }),
        ),
      );
    }

    if (profile.fingerprint.stable_hash) {
      tier1Writes.push(
        this.client.send(
          new PutItemCommand({
            TableName: this.config.tier1IndexTable,
            Item: marshall({
              tenant_id: profile.tenantId,
              hash_key: `stable#${profile.fingerprint.stable_hash}`,
              device_id: profile.deviceId,
              risk_score: profile.riskScore ?? 0.3,
              flags: profile.flags ?? [],
              ttl,
            }),
          }),
        ),
      );
    }

    if (profile.fingerprint.fuzzy_hash) {
      tier1Writes.push(
        this.client.send(
          new PutItemCommand({
            TableName: this.config.tier1IndexTable,
            Item: marshall({
              tenant_id: profile.tenantId,
              hash_key: `fuzzy#${profile.fingerprint.fuzzy_hash}`,
              device_id: profile.deviceId,
              risk_score: profile.riskScore ?? 0.3,
              flags: profile.flags ?? [],
              ttl,
            }),
          }),
        ),
      );
    }

    await Promise.all(tier1Writes);

    // 3. Write Tier 2 bucket entries
    const tier2Writes: Promise<unknown>[] = [];
    const fp = profile.fingerprint;

    // IP + JA4 bucket
    if (fp.ip_address && fp.ja4) {
      const bucketKey = `${profile.tenantId}#ip_ja4#${fp.ip_address}#${fp.ja4}`;
      tier2Writes.push(
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
    }

    // GPU + Screen + Timezone bucket
    if (fp.gpu_renderer && fp.screen_dims && fp.timezone) {
      const bucketKey = `${profile.tenantId}#gpu_screen_tz#${fp.gpu_renderer}#${fp.screen_dims}#${fp.timezone}`;
      tier2Writes.push(
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
    }

    // Audio + Canvas bucket
    if (fp.audio_hash && fp.canvas_hash) {
      const bucketKey = `${profile.tenantId}#audio_canvas#${fp.audio_hash}#${fp.canvas_hash}`;
      tier2Writes.push(
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
    }

    await Promise.all(tier2Writes);
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
    // 1. Get the profile to find associated hashes
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

    if (profileResult.Items && profileResult.Items.length > 0) {
      const profile = unmarshall(profileResult.Items[0]);

      // Delete Tier 1 indexes
      const deletePromises: Promise<unknown>[] = [];

      if (profile.stable_hash) {
        deletePromises.push(
          this.client.send(
            new DeleteItemCommand({
              TableName: this.config.tier1IndexTable,
              Key: marshall({
                tenant_id: tenantId,
                hash_key: `stable#${profile.stable_hash}`,
              }),
            }),
          ),
        );
      }

      if (profile.fuzzy_hash) {
        deletePromises.push(
          this.client.send(
            new DeleteItemCommand({
              TableName: this.config.tier1IndexTable,
              Key: marshall({
                tenant_id: tenantId,
                hash_key: `fuzzy#${profile.fuzzy_hash}`,
              }),
            }),
          ),
        );
      }

      await Promise.all(deletePromises);
    }

    // 2. Delete profile
    await this.client.send(
      new DeleteItemCommand({
        TableName: this.config.profilesTable,
        Key: marshall({
          tenant_id: tenantId,
          device_id: deviceId,
        }),
      }),
    );

    // Note: Tier 2 bucket entries will expire via TTL
    // For immediate cleanup, would need to track bucket keys
  }

  /**
   * Cleanup all data for a tenant
   * WARNING: Use only for test tenants!
   */
  async cleanupTenant(
    tenantId: string,
  ): Promise<{ profilesDeleted: number; indexesDeleted: number }> {
    let profilesDeleted = 0;
    let indexesDeleted = 0;

    // 1. Delete all profiles for tenant
    let lastEvaluatedKey: Record<string, unknown> | undefined;
    do {
      const result = await this.client.send(
        new QueryCommand({
          TableName: this.config.profilesTable,
          KeyConditionExpression: "tenant_id = :tid",
          ExpressionAttributeValues: {
            ":tid": { S: tenantId },
          },
          ProjectionExpression: "tenant_id, device_id",
          ExclusiveStartKey: lastEvaluatedKey as Record<string, { S: string }>,
        }),
      );

      if (result.Items && result.Items.length > 0) {
        // Batch delete profiles (max 25 per batch)
        const batches = [];
        for (let i = 0; i < result.Items.length; i += 25) {
          const batch = result.Items.slice(i, i + 25);
          batches.push(
            this.client.send(
              new BatchWriteItemCommand({
                RequestItems: {
                  [this.config.profilesTable]: batch.map((item) => ({
                    DeleteRequest: {
                      Key: {
                        tenant_id: item.tenant_id,
                        device_id: item.device_id,
                      },
                    },
                  })),
                },
              }),
            ),
          );
        }
        await Promise.all(batches);
        profilesDeleted += result.Items.length;
      }

      lastEvaluatedKey = result.LastEvaluatedKey as
        | Record<string, unknown>
        | undefined;
    } while (lastEvaluatedKey);

    // 2. Delete all Tier 1 indexes for tenant
    lastEvaluatedKey = undefined;
    do {
      const result = await this.client.send(
        new QueryCommand({
          TableName: this.config.tier1IndexTable,
          KeyConditionExpression: "tenant_id = :tid",
          ExpressionAttributeValues: {
            ":tid": { S: tenantId },
          },
          ProjectionExpression: "tenant_id, hash_key",
          ExclusiveStartKey: lastEvaluatedKey as Record<string, { S: string }>,
        }),
      );

      if (result.Items && result.Items.length > 0) {
        const batches = [];
        for (let i = 0; i < result.Items.length; i += 25) {
          const batch = result.Items.slice(i, i + 25);
          batches.push(
            this.client.send(
              new BatchWriteItemCommand({
                RequestItems: {
                  [this.config.tier1IndexTable]: batch.map((item) => ({
                    DeleteRequest: {
                      Key: {
                        tenant_id: item.tenant_id,
                        hash_key: item.hash_key,
                      },
                    },
                  })),
                },
              }),
            ),
          );
        }
        await Promise.all(batches);
        indexesDeleted += result.Items.length;
      }

      lastEvaluatedKey = result.LastEvaluatedKey as
        | Record<string, unknown>
        | undefined;
    } while (lastEvaluatedKey);

    // Note: Tier 2 bucket cleanup requires knowing bucket keys or scanning
    // For test purposes, TTL-based expiration is typically sufficient

    return { profilesDeleted, indexesDeleted };
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
        KeyConditionExpression: "tenant_id = :tid",
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
