// src/services/profile/index-writers.ts
// AR-120: Extracted index writing logic from profile-service.ts
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  WriteRequest,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { Fingerprint } from "./types";
import {
  TIER2_STATS_SK,
  SESSION_ANCHOR_CLEANUP_TTL_SECONDS,
} from "../../helpers/constants";
import {
  buildTier2BucketKeys as buildTier2BucketKeysHelper,
  buildSessionAnchorKey as buildSessionAnchorKeyHelper,
  buildIpUaAnchorKey as buildIpUaAnchorKeyHelper,
} from "../../helpers/bucket-keys";

/**
 * Type for Tier 1 index entry
 */
export interface Tier1IndexEntry {
  hash_key: string;
  device_id: string;
  ttl: number;
}

/**
 * Type for Tier 2 bucket entry
 */
export interface Tier2BucketEntry {
  bucket_key: string;
  device_id: string;
  ttl: number;
}

/**
 * Dependencies for index writer operations
 */
export interface IndexWriterDeps {
  dynamodb: DynamoDBClient;
  tier1IndexTable: string;
  tier2BucketsTable: string;
}

/**
 * Sleep utility for retry backoff
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Build Tier 1 index entries for a fingerprint
 */
export function buildTier1IndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const entries: Tier1IndexEntry[] = [];

  if (fingerprint.evercookie_id) {
    entries.push({
      hash_key: `evercookie#${fingerprint.evercookie_id}`,
      device_id: deviceId,
      ttl,
    });
  }

  // AR-81: Third-party cookie from sigint CloudFront edge
  if (fingerprint.sigint_id) {
    entries.push({
      hash_key: `sigint#${fingerprint.sigint_id}`,
      device_id: deviceId,
      ttl,
    });
  }

  // AR-64: ECDSA public key for cryptographic device identity
  if (fingerprint.public_key) {
    entries.push({
      hash_key: `pubkey#${fingerprint.public_key}`,
      device_id: deviceId,
      ttl,
    });
  }

  if (fingerprint.stable_hash) {
    entries.push({
      hash_key: `stable#${fingerprint.stable_hash}`,
      device_id: deviceId,
      ttl,
    });
  }

  if (fingerprint.fuzzy_hash) {
    entries.push({
      hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
      device_id: deviceId,
      ttl,
    });
  }

  // AR-115: Removed standalone ja4# indexing - JA4 alone is not unique enough
  // for direct matching (many devices share the same JA4). JA4 is still used
  // in Tier2 compound buckets (ip_ja4) where it's combined with other signals.

  return entries;
}

/**
 * Batch write Tier 1 index entries with retry logic for unprocessed items
 */
export async function batchWriteTier1Indexes(
  deps: IndexWriterDeps,
  entries: Tier1IndexEntry[],
  maxRetries: number = 3,
): Promise<void> {
  const tableName = deps.tier1IndexTable;
  let unprocessedItems: WriteRequest[] = entries.map((entry) => ({
    PutRequest: {
      Item: marshall(entry),
    },
  }));

  let attempt = 0;

  while (unprocessedItems.length > 0 && attempt < maxRetries) {
    const result = await deps.dynamodb.send(
      new BatchWriteItemCommand({
        RequestItems: {
          [tableName]: unprocessedItems,
        },
      }),
    );

    // Check for unprocessed items (can happen during throttling)
    const remaining = result.UnprocessedItems?.[tableName];
    if (remaining && remaining.length > 0) {
      unprocessedItems = remaining;
      attempt++;
      // Exponential backoff: 100ms, 200ms, 400ms
      await sleep(Math.pow(2, attempt) * 100);
    } else {
      unprocessedItems = [];
    }
  }

  if (unprocessedItems.length > 0) {
    throw new Error(
      `Failed to write ${unprocessedItems.length} Tier1 index items after ${maxRetries} retries`,
    );
  }
}

/**
 * Build Tier 2 bucket keys for compound matching
 * AR-117: Delegates to shared bucket-keys helper
 */
export function buildTier2BucketKeys(fingerprint: Fingerprint): string[] {
  return buildTier2BucketKeysHelper(fingerprint);
}

/**
 * Batch write Tier 2 bucket entries with retry logic for unprocessed items (AR-40)
 */
export async function batchWriteTier2Buckets(
  deps: IndexWriterDeps,
  entries: Tier2BucketEntry[],
  maxRetries: number = 3,
): Promise<void> {
  const tableName = deps.tier2BucketsTable;
  let unprocessedItems: WriteRequest[] = entries.map((entry) => ({
    PutRequest: {
      Item: {
        bucket_key: { S: entry.bucket_key },
        device_id: { S: entry.device_id },
        ttl: { N: String(entry.ttl) },
      },
    },
  }));

  let attempt = 0;

  while (unprocessedItems.length > 0 && attempt < maxRetries) {
    const result = await deps.dynamodb.send(
      new BatchWriteItemCommand({
        RequestItems: {
          [tableName]: unprocessedItems,
        },
      }),
    );

    // Check for unprocessed items (can happen during throttling)
    const remaining = result.UnprocessedItems?.[tableName];
    if (remaining && remaining.length > 0) {
      unprocessedItems = remaining;
      attempt++;
      // Exponential backoff: 100ms, 200ms, 400ms
      await sleep(Math.pow(2, attempt) * 100);
    } else {
      unprocessedItems = [];
    }
  }

  if (unprocessedItems.length > 0) {
    throw new Error(
      `Failed to write ${unprocessedItems.length} Tier2 bucket items after ${maxRetries} retries`,
    );
  }
}

/**
 * AR-56: Increment cardinality counters for Tier 2 buckets
 * Uses UpdateItem with ADD for atomic increment
 * Stats items use "_stats" as sort key to distinguish from device entries
 */
export async function incrementBucketCardinalities(
  deps: IndexWriterDeps,
  bucketKeys: string[],
  ttl: number,
): Promise<void> {
  const tableName = deps.tier2BucketsTable;

  // Increment all counters in parallel
  const updates = bucketKeys.map((bucketKey) =>
    deps.dynamodb.send(
      new UpdateItemCommand({
        TableName: tableName,
        Key: {
          bucket_key: { S: bucketKey },
          device_id: { S: TIER2_STATS_SK },
        },
        UpdateExpression: "ADD cardinality :inc SET #ttl = :ttl",
        ExpressionAttributeNames: {
          "#ttl": "ttl",
        },
        ExpressionAttributeValues: {
          ":inc": { N: "1" },
          ":ttl": { N: String(ttl) },
        },
      }),
    ),
  );

  await Promise.all(updates);
}

/**
 * AR-82: Build session anchor bucket key for ephemeral short-window matching
 * AR-117: Delegates to shared bucket-keys helper
 */
export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  return buildSessionAnchorKeyHelper(fingerprint);
}

/**
 * AR-82: Write session anchor bucket for ephemeral matching
 * Stores created_at timestamp for application-side 10-minute validity check
 * Uses shorter TTL (1 hour) for DynamoDB cleanup
 */
export async function writeSessionAnchorBucket(
  deps: IndexWriterDeps,
  bucketKey: string,
  deviceId: string,
): Promise<void> {
  const now = Date.now();
  const ttl = Math.floor(now / 1000) + SESSION_ANCHOR_CLEANUP_TTL_SECONDS;

  await deps.dynamodb.send(
    new PutItemCommand({
      TableName: deps.tier2BucketsTable,
      Item: {
        bucket_key: { S: bucketKey },
        device_id: { S: deviceId },
        created_at: { N: String(now) },
        ttl: { N: String(ttl) },
      },
    }),
  );
}

/**
 * AR-94: Build IP+UA-only anchor bucket key for ephemeral matching
 * AR-117: Delegates to shared bucket-keys helper
 */
export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  return buildIpUaAnchorKeyHelper(fingerprint);
}

/**
 * AR-94: Write IP+UA-only anchor bucket for ephemeral matching
 * Stores created_at timestamp for application-side 3-minute validity check
 * Uses 1 hour TTL for DynamoDB cleanup (same as session anchor)
 */
export async function writeIpUaAnchorBucket(
  deps: IndexWriterDeps,
  bucketKey: string,
  deviceId: string,
): Promise<void> {
  const now = Date.now();
  const ttl = Math.floor(now / 1000) + SESSION_ANCHOR_CLEANUP_TTL_SECONDS;

  await deps.dynamodb.send(
    new PutItemCommand({
      TableName: deps.tier2BucketsTable,
      Item: {
        bucket_key: { S: bucketKey },
        device_id: { S: deviceId },
        created_at: { N: String(now) },
        ttl: { N: String(ttl) },
      },
    }),
  );
}
