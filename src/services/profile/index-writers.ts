// src/services/profile/index-writers.ts

import {
  DynamoDBClient,
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
  buildSimHashBandKeys,
  buildSimHashBandSK,
} from "../../helpers/bucket-keys";
import { batchWriteWithRetry } from "../../helpers/batch-write";

/**
 * Evidence codes that permit identity association
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
 * Added fuzzy_hash for drift detection at match time
 */
export interface Tier1IndexEntry {
  hash_key: string;
  device_id: string;
  /** Device's fuzzy_hash at time of index write, for drift comparison */
  fuzzy_hash?: string;
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
 * Build Tier 1 index entries for a fingerprint
 * Added fuzzy_hash to all entries for drift detection at match time
 */
export function buildTier1IndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const entries: Tier1IndexEntry[] = [];
  // Include fuzzy_hash in all entries for drift comparison at match time
  const fuzzyHash = fingerprint.fuzzy_hash;

  if (fingerprint.evercookie_id) {
    entries.push({
      hash_key: `evercookie#${fingerprint.evercookie_id}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  // Third-party cookie from sigint CloudFront edge
  if (fingerprint.sigint_id) {
    entries.push({
      hash_key: `sigint#${fingerprint.sigint_id}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  // ECDSA public key for cryptographic device identity
  if (fingerprint.public_key) {
    entries.push({
      hash_key: `pubkey#${fingerprint.public_key}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  if (fingerprint.stable_hash) {
    entries.push({
      hash_key: `stable#${fingerprint.stable_hash}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  if (fingerprint.fuzzy_hash) {
    entries.push({
      hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  // Removed standalone ja4# indexing - JA4 alone is not unique enough
  // for direct matching (many devices share the same JA4). JA4 is still used
  // in Tier2 compound buckets (ip_ja4) where it's combined with other signals.

  return entries;
}

/**
 * Build identity index entries only (pubkey#, evercookie#, sigint#)
 * These are the indexes that link crypto-id/evercookie to device_id.
 * Only write these for high-confidence matches to prevent viral spreading.
 * Added fuzzy_hash for drift detection at match time
 */
export function buildIdentityIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const entries: Tier1IndexEntry[] = [];
  // Include fuzzy_hash for drift comparison at match time
  const fuzzyHash = fingerprint.fuzzy_hash;

  if (fingerprint.evercookie_id) {
    entries.push({
      hash_key: `evercookie#${fingerprint.evercookie_id}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  // Third-party cookie from sigint CloudFront edge
  if (fingerprint.sigint_id) {
    entries.push({
      hash_key: `sigint#${fingerprint.sigint_id}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  // ECDSA public key for cryptographic device identity
  if (fingerprint.public_key) {
    entries.push({
      hash_key: `pubkey#${fingerprint.public_key}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  return entries;
}

/**
 * Build hash index entries only (stable#, fuzzy#)
 * These indexes enable fingerprint-based lookups.
 * Always written regardless of match tier.
 * Added fuzzy_hash for drift detection at match time
 */
export function buildHashIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const entries: Tier1IndexEntry[] = [];
  // Include fuzzy_hash for drift comparison at match time
  const fuzzyHash = fingerprint.fuzzy_hash;

  if (fingerprint.stable_hash) {
    entries.push({
      hash_key: `stable#${fingerprint.stable_hash}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  if (fingerprint.fuzzy_hash) {
    entries.push({
      hash_key: `fuzzy#${fingerprint.fuzzy_hash}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    });
  }

  return entries;
}

/**
 * Batch write Tier 1 index entries with retry logic for unprocessed items
 * Uses removeUndefinedValues to handle optional fuzzy_hash
 */
export async function batchWriteTier1Indexes(
  deps: IndexWriterDeps,
  entries: Tier1IndexEntry[],
  maxRetries: number = 3,
): Promise<void> {
  const items: WriteRequest[] = entries.map((entry) => ({
    PutRequest: {
      Item: marshall(entry, { removeUndefinedValues: true }),
    },
  }));
  await batchWriteWithRetry(
    deps.dynamodb,
    deps.tier1IndexTable,
    items,
    "Tier1 index",
    maxRetries,
  );
}

/**
 * Batch write Tier 2 bucket entries with retry logic for unprocessed items
 */
export async function batchWriteTier2Buckets(
  deps: IndexWriterDeps,
  entries: Tier2BucketEntry[],
  maxRetries: number = 3,
): Promise<void> {
  const items: WriteRequest[] = entries.map((entry) => ({
    PutRequest: {
      Item: {
        bucket_key: { S: entry.bucket_key },
        device_id: { S: entry.device_id },
        ttl: { N: String(entry.ttl) },
      },
    },
  }));
  await batchWriteWithRetry(
    deps.dynamodb,
    deps.tier2BucketsTable,
    items,
    "Tier2 bucket",
    maxRetries,
  );
}

/**
 * Increment cardinality counters for Tier 2 buckets
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
 * Write anchor bucket entry for ephemeral matching.
 * Used for both session anchors and IP+UA anchors.
 * Stores created_at for application-side validity check.
 * Uses SESSION_ANCHOR_CLEANUP_TTL for DynamoDB TTL cleanup.
 */
export async function writeAnchorBucket(
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
 * Type for SimHash LSH band entry
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
 * Build SimHash LSH band entries for a fingerprint
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
 * Batch write SimHash LSH band entries with retry logic
 * Uses tier2BucketsTable with special PK format for band entries
 */
export async function batchWriteSimHashBands(
  deps: IndexWriterDeps,
  entries: SimHashBandEntry[],
  maxRetries: number = 3,
): Promise<void> {
  const items: WriteRequest[] = entries.map((entry) => ({
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
  await batchWriteWithRetry(
    deps.dynamodb,
    deps.tier2BucketsTable,
    items,
    "SimHash band",
    maxRetries,
  );
}
