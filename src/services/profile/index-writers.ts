// src/services/profile/index-writers.ts
// AR-120: Extracted index writing logic from profile-service.ts
// AR-150: Added tier-gated identity association
// AR-XXX: Added SimHash LSH band entry writing for Tier 1.5

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
  SIMHASH_CONFIG,
} from "../../helpers/constants";
import {
  buildTier2BucketKeys as buildTier2BucketKeysHelper,
  buildSessionAnchorKey as buildSessionAnchorKeyHelper,
  buildIpUaAnchorKey as buildIpUaAnchorKeyHelper,
  buildSimHashBandKeys,
  buildSimHashBandSK,
} from "../../helpers/bucket-keys";

/**
 * AR-150: Evidence codes that permit identity association
 *
 * Only these match types should create identity indexes (pubkey#, evercookie#, sigint#).
 * Tier 2 unbounded matches (IP_JA4_BUCKET, GPU_SCREEN_TZ_BUCKET, etc.) are excluded
 * to prevent viral spreading of device_ids across unrelated users.
 *
 * Includes:
 * - Tier 0.5: Identity matches (PUBLIC_KEY_MATCH, EVERCOOKIE_MATCH, SIGINT_ID_MATCH)
 * - Tier 1: Hash matches (STABLE_HASH_MATCH, FUZZY_HASH_MATCH)
 * - Time-bounded anchors: SESSION_ANCHOR_BUCKET (10min), IP_UA_ANCHOR_BUCKET (3min)
 * - NEW_DEVICE: First time seeing this device, must create indexes for future lookups
 *
 * Excludes:
 * - Tier 2 unbounded: IP_JA4_BUCKET, GPU_SCREEN_TZ_BUCKET, AUDIO_CANVAS_BUCKET, etc.
 */
export const ASSOCIATION_ALLOWED_EVIDENCE: readonly string[] = [
  // Tier 0.5: Identity matches (highest confidence)
  "PUBLIC_KEY_MATCH",
  "EVERCOOKIE_MATCH",
  "SIGINT_ID_MATCH",
  // Tier 1: Hash matches (high confidence)
  "STABLE_HASH_MATCH",
  "FUZZY_HASH_MATCH",
  // Tier 1.5: SimHash LSH match (high confidence - drift detection)
  "SIMHASH_MATCH",
  // Time-bounded anchors (medium-high confidence, decay quickly)
  "SESSION_ANCHOR_BUCKET",
  "IP_UA_ANCHOR_BUCKET",
  // New device: Must create indexes for future lookups to work
  "NEW_DEVICE",
] as const;

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
 * AR-150: Build identity index entries only (pubkey#, evercookie#, sigint#)
 * These are the indexes that link crypto-id/evercookie to device_id.
 * Only write these for high-confidence matches to prevent viral spreading.
 */
export function buildIdentityIndexEntries(
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

  return entries;
}

/**
 * AR-150: Build hash index entries only (stable#, fuzzy#)
 * These indexes enable fingerprint-based lookups.
 * Always written regardless of match tier.
 */
export function buildHashIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const entries: Tier1IndexEntry[] = [];

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

// ==================== SIMHASH LSH BAND ENTRIES (Tier 1.5) ====================

/**
 * AR-XXX: Type for SimHash LSH band entry
 * Stored in tier2BucketsTable with special PK format
 *
 * Schema:
 * - PK (bucket_key): SIMHASH_BAND#<band_index>#<band_value_hex>
 * - SK (device_id): t#<inverted_timestamp>#<device_id> (recency-ordered)
 * - fuzzy_hash: Full 64-bit hash for inline Hamming scoring
 * - last_seen: Unix timestamp for recency gate
 * - ttl: DynamoDB TTL for auto-expiration
 */
export interface SimHashBandEntry {
  bucket_key: string; // PK: SIMHASH_BAND#0#a1b2
  device_id: string; // SK: t#<inverted_ts>#dev_xxx (recency-ordered)
  fuzzy_hash: string; // Full hash for Hamming distance scoring
  last_seen: number; // Unix timestamp in seconds
  ttl: number; // TTL for DynamoDB expiration
}

/**
 * AR-XXX: Build SimHash LSH band entries for a fingerprint
 * Creates 4 band entries (one per band) with inline hash for scoring
 *
 * @param deviceId - The device ID
 * @param fingerprint - Fingerprint containing fuzzy_hash
 * @param timestamp - Unix timestamp in seconds (defaults to now)
 * @returns Array of 4 band entries, or empty array if fuzzy_hash is missing/invalid
 */
export function buildSimHashBandEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  timestamp: number = Math.floor(Date.now() / 1000),
): SimHashBandEntry[] {
  const bandKeys = buildSimHashBandKeys(fingerprint.fuzzy_hash);
  if (!bandKeys) return [];

  const ttl = timestamp + SIMHASH_CONFIG.BAND_TTL_DAYS * 86400;
  const sk = buildSimHashBandSK(deviceId, timestamp);

  return bandKeys.map((band) => ({
    bucket_key: band.pk,
    device_id: sk,
    fuzzy_hash: fingerprint.fuzzy_hash!,
    last_seen: timestamp,
    ttl,
  }));
}

/**
 * AR-XXX: Batch write SimHash LSH band entries with retry logic
 * Uses tier2BucketsTable with special PK format for band entries
 */
export async function batchWriteSimHashBands(
  deps: IndexWriterDeps,
  entries: SimHashBandEntry[],
  maxRetries: number = 3,
): Promise<void> {
  if (entries.length === 0) return;

  const tableName = deps.tier2BucketsTable;
  let unprocessedItems: WriteRequest[] = entries.map((entry) => ({
    PutRequest: {
      Item: {
        bucket_key: { S: entry.bucket_key },
        device_id: { S: entry.device_id },
        fuzzy_hash: { S: entry.fuzzy_hash },
        last_seen: { N: String(entry.last_seen) },
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
      `Failed to write ${unprocessedItems.length} SimHash band items after ${maxRetries} retries`,
    );
  }
}
