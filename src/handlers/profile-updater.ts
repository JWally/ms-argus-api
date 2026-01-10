// src/handlers/profile-updater.ts
import { SQSHandler, SQSBatchResponse, SQSBatchItemFailure, SQSRecord } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { Metrics, MetricUnit } from '@aws-lambda-powertools/metrics';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import Redis from 'ioredis';

const logger = new Logger({ serviceName: process.env.POWERTOOLS_SERVICE_NAME });
const tracer = new Tracer({ serviceName: process.env.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({ namespace: process.env.POWERTOOLS_METRICS_NAMESPACE });

const dynamodb = tracer.captureAWSv3Client(new DynamoDBClient({}));

// Redis connection (for mutation gate check)
let redis: Redis | null = null;

function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      host: process.env.REDIS_ENDPOINT!,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      tls: {},
      maxRetriesPerRequest: 3,
      retryStrategy: (times: number) => Math.min(times * 100, 2000),
    });
  }
  return redis;
}

// Profile update payload from matching worker
interface ProfileUpdatePayload {
  tenant_id: string;
  device_id: string;
  fingerprint: {
    stable_hash?: string;
    fuzzy_hash?: string;
    canvas_hash?: string;
    webgl_hash?: string;
    audio_hash?: string;
    ip_address?: string;
    ja4?: string;
    gpu_renderer?: string;
    screen_dims?: string;
    timezone?: string;
    evercookie_id?: string;
  };
  tcp_blob?: string;
  tls_blob?: string;
  timestamp: number;
}

// TTL: 60 days from now
const TTL_SECONDS = 60 * 24 * 60 * 60;
const MUTATION_GATE_TTL = 3600; // 1 hour

/**
 * Profile Updater Lambda Handler
 * Writes device profiles and indexes to DynamoDB
 * Implements mutation gating to reduce unnecessary writes
 */
export const handler: SQSHandler = async (event): Promise<SQSBatchResponse> => {
  const batchItemFailures: SQSBatchItemFailure[] = [];

  for (const record of event.Records) {
    try {
      await processRecord(record);
      metrics.addMetric('ProfileUpdateSuccess', MetricUnit.Count, 1);
    } catch (error) {
      logger.error('Failed to process record', { error, messageId: record.messageId });
      metrics.addMetric('ProfileUpdateError', MetricUnit.Count, 1);
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }

  metrics.publishStoredMetrics();
  return { batchItemFailures };
};

async function processRecord(record: SQSRecord): Promise<void> {
  const startTime = Date.now();
  const payload: ProfileUpdatePayload = JSON.parse(record.body);
  const { tenant_id, device_id, fingerprint, timestamp } = payload;

  logger.info('Processing profile update', { tenant_id, device_id });

  // Mutation gate check - skip if recently updated
  const shouldUpdate = await checkMutationGate(device_id);
  if (!shouldUpdate) {
    metrics.addMetric('MutationGateSkip', MetricUnit.Count, 1);
    logger.info('Skipping update - recently updated', { device_id });
    return;
  }

  // Load existing profile to check for drift
  const existingProfile = await loadExistingProfile(tenant_id, device_id);

  // Check if fingerprint has drifted enough to warrant update
  if (existingProfile && !hasSignificantDrift(existingProfile, fingerprint)) {
    metrics.addMetric('NoDriftSkip', MetricUnit.Count, 1);
    logger.info('Skipping update - no significant drift', { device_id });
    // Still update mutation gate timestamp
    await setMutationGate(device_id);
    return;
  }

  // Update profile
  await updateProfile(tenant_id, device_id, fingerprint, timestamp, existingProfile);

  // Update Tier 1 indexes
  await updateTier1Indexes(tenant_id, device_id, fingerprint);

  // Update Tier 2 buckets
  await updateTier2Buckets(tenant_id, device_id, fingerprint);

  // TODO: Update Qdrant vectors when Qdrant stack is deployed
  // await updateVectorEmbedding(tenant_id, device_id, fingerprint);

  // Set mutation gate
  await setMutationGate(device_id);

  const duration = Date.now() - startTime;
  metrics.addMetric('ProfileUpdateDuration', MetricUnit.Milliseconds, duration);
  logger.info('Profile update complete', { tenant_id, device_id, duration });
}

async function checkMutationGate(deviceId: string): Promise<boolean> {
  const redis = getRedis();
  const key = `recently_updated:${deviceId}`;
  const exists = await redis.exists(key);
  return exists === 0; // Update if key doesn't exist
}

async function setMutationGate(deviceId: string): Promise<void> {
  const redis = getRedis();
  const key = `recently_updated:${deviceId}`;
  await redis.setex(key, MUTATION_GATE_TTL, '1');
}

async function loadExistingProfile(
  tenantId: string,
  deviceId: string,
): Promise<Record<string, unknown> | null> {
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: process.env.PROFILES_TABLE,
      Key: {
        tenant_id: { S: tenantId },
        device_id: { S: deviceId },
      },
    }),
  );

  return result.Item ? unmarshall(result.Item) : null;
}

function hasSignificantDrift(
  existing: Record<string, unknown>,
  incoming: ProfileUpdatePayload['fingerprint'],
): boolean {
  // Check if stable hash changed (major drift)
  if (existing.stable_hash !== incoming.stable_hash) {
    return true;
  }

  // Check if multiple signals changed (accumulated drift)
  let changedSignals = 0;

  if (existing.canvas_hash !== incoming.canvas_hash) changedSignals++;
  if (existing.webgl_hash !== incoming.webgl_hash) changedSignals++;
  if (existing.audio_hash !== incoming.audio_hash) changedSignals++;
  if (existing.gpu_renderer !== incoming.gpu_renderer) changedSignals++;
  if (existing.screen_dims !== incoming.screen_dims) changedSignals++;

  // Drift threshold: 2+ signals changed
  return changedSignals >= 2;
}

async function updateProfile(
  tenantId: string,
  deviceId: string,
  fingerprint: ProfileUpdatePayload['fingerprint'],
  timestamp: number,
  existingProfile: Record<string, unknown> | null,
): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + TTL_SECONDS;
  const now = Date.now();

  // Calculate updated hour bucket for last_seen (only update if hour changed)
  const currentHour = Math.floor(now / 3600000);
  const existingHour = existingProfile
    ? Math.floor((existingProfile.last_seen_at as number) / 3600000)
    : 0;
  const shouldUpdateLastSeen = currentHour !== existingHour;

  const profileData: Record<string, unknown> = {
    tenant_id: tenantId,
    device_id: deviceId,
    ...fingerprint,
    first_seen_at: existingProfile?.first_seen_at || now,
    last_seen_at: shouldUpdateLastSeen ? now : existingProfile?.last_seen_at || now,
    request_count: ((existingProfile?.request_count as number) || 0) + 1,
    updated_at: now,
    ttl,
  };

  // Preserve existing risk score and flags
  if (existingProfile) {
    profileData.risk_score = existingProfile.risk_score;
    profileData.flags = existingProfile.flags;
  } else {
    profileData.risk_score = 0.5; // Neutral for new profiles
    profileData.flags = [];
  }

  await dynamodb.send(
    new PutItemCommand({
      TableName: process.env.PROFILES_TABLE,
      Item: marshall(profileData, { removeUndefinedValues: true }),
    }),
  );

  metrics.addMetric('ProfileWrite', MetricUnit.Count, 1);
}

async function updateTier1Indexes(
  tenantId: string,
  deviceId: string,
  fingerprint: ProfileUpdatePayload['fingerprint'],
): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + TTL_SECONDS;
  const writes: Promise<unknown>[] = [];

  // Index by evercookie_id
  if (fingerprint.evercookie_id) {
    writes.push(
      dynamodb.send(
        new PutItemCommand({
          TableName: process.env.TIER1_INDEX_TABLE,
          Item: marshall({
            tenant_id: tenantId,
            hash_key: `evercookie#${fingerprint.evercookie_id}`,
            device_id: deviceId,
            ttl,
          }),
        }),
      ),
    );
  }

  // Index by stable_hash
  if (fingerprint.stable_hash) {
    writes.push(
      dynamodb.send(
        new PutItemCommand({
          TableName: process.env.TIER1_INDEX_TABLE,
          Item: marshall({
            tenant_id: tenantId,
            hash_key: `stable#${fingerprint.stable_hash}`,
            device_id: deviceId,
            ttl,
          }),
        }),
      ),
    );
  }

  // Index by fuzzy_hash
  if (fingerprint.fuzzy_hash) {
    writes.push(
      dynamodb.send(
        new PutItemCommand({
          TableName: process.env.TIER1_INDEX_TABLE,
          Item: marshall({
            tenant_id: tenantId,
            hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
            device_id: deviceId,
            ttl,
          }),
        }),
      ),
    );
  }

  // Index by ja4
  if (fingerprint.ja4) {
    writes.push(
      dynamodb.send(
        new PutItemCommand({
          TableName: process.env.TIER1_INDEX_TABLE,
          Item: marshall({
            tenant_id: tenantId,
            hash_key: `ja4#${fingerprint.ja4}`,
            device_id: deviceId,
            ttl,
          }),
        }),
      ),
    );
  }

  await Promise.all(writes);
  metrics.addMetric('Tier1IndexWrites', MetricUnit.Count, writes.length);
}

async function updateTier2Buckets(
  tenantId: string,
  deviceId: string,
  fingerprint: ProfileUpdatePayload['fingerprint'],
): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + TTL_SECONDS;
  const updates: Promise<unknown>[] = [];

  // IP + JA4 bucket
  if (fingerprint.ip_address && fingerprint.ja4) {
    const bucketKey = `${tenantId}#ip_ja4#${fingerprint.ip_address}#${fingerprint.ja4}`;
    updates.push(addDeviceToBucket(bucketKey, deviceId, ttl));
  }

  // GPU + Screen + Timezone bucket
  if (fingerprint.gpu_renderer && fingerprint.screen_dims && fingerprint.timezone) {
    const bucketKey = `${tenantId}#gpu_screen_tz#${fingerprint.gpu_renderer}#${fingerprint.screen_dims}#${fingerprint.timezone}`;
    updates.push(addDeviceToBucket(bucketKey, deviceId, ttl));
  }

  // Audio + Canvas bucket
  if (fingerprint.audio_hash && fingerprint.canvas_hash) {
    const bucketKey = `${tenantId}#audio_canvas#${fingerprint.audio_hash}#${fingerprint.canvas_hash}`;
    updates.push(addDeviceToBucket(bucketKey, deviceId, ttl));
  }

  await Promise.all(updates);
  metrics.addMetric('Tier2BucketWrites', MetricUnit.Count, updates.length);
}

async function addDeviceToBucket(bucketKey: string, deviceId: string, ttl: number): Promise<void> {
  // Use UpdateItem with ADD to append device_id to the set
  // This is more efficient than GET + PUT for high-contention buckets
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: process.env.TIER2_BUCKETS_TABLE,
      Key: { bucket_key: { S: bucketKey } },
      UpdateExpression: 'ADD device_ids :device_id SET #ttl = :ttl',
      ExpressionAttributeNames: { '#ttl': 'ttl' },
      ExpressionAttributeValues: {
        ':device_id': { SS: [deviceId] },
        ':ttl': { N: String(ttl) },
      },
    }),
  );
}
