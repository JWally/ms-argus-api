import {
  DynamoDBClient,
  PutItemCommand,
  WriteRequest,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { Fingerprint } from "./types";
import {
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
 *
 * Includes:
 * - Tier 0.5: Identity matches (PUBLIC_KEY_MATCH, EVERCOOKIE_MATCH, SIGINT_ID_MATCH)
 * - Tier 1: Hash matches (STABLE_HASH_MATCH, FUZZY_HASH_MATCH)
 * - Tier 1.5: SimHash LSH matches (SIMHASH_MATCH)
 * - Time-bounded anchors: SESSION_ANCHOR_BUCKET (10min), IP_UA_ANCHOR_BUCKET (3min)
 * - NEW_DEVICE: First time seeing this device, must create indexes for future lookups
 */
export const ASSOCIATION_ALLOWED_EVIDENCE: readonly string[] = [
  "PUBLIC_KEY_MATCH",
  "EVERCOOKIE_MATCH",
  "SIGINT_ID_MATCH",
  "STABLE_HASH_MATCH",
  "FUZZY_HASH_MATCH",
  "SIMHASH_MATCH",
  "SESSION_ANCHOR_BUCKET",
  "IP_UA_ANCHOR_BUCKET",
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
 * Dependencies for index writer operations
 */
export interface IndexWriterDeps {
  dynamodb: DynamoDBClient;
  tier1IndexTable: string;
  tier2BucketsTable: string;
}

const INDEX_FIELDS: {
  field: keyof Fingerprint;
  prefix: string;
  group: "identity" | "hash";
}[] = [
  { field: "evercookie_id", prefix: "evercookie#", group: "identity" },
  { field: "sigint_id", prefix: "sigint#", group: "identity" },
  { field: "public_key", prefix: "pubkey#", group: "identity" },
  { field: "stable_hash", prefix: "stable#", group: "hash" },
  { field: "fuzzy_hash", prefix: "fuzzy#", group: "hash" },
];

/**
 * Build Tier 1 index entries for a device
 * @param deviceId - The device ID to index
 * @param fingerprint - The fingerprint containing index values
 * @param ttl - TTL timestamp for DynamoDB expiration
 * @param filter - Optional filter to build only identity or hash indexes
 * @returns Array of index entries to write
 */
function buildIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
  filter?: "identity" | "hash",
): Tier1IndexEntry[] {
  const fuzzyHash = fingerprint.fuzzy_hash;
  return INDEX_FIELDS.filter((f) => !filter || f.group === filter)
    .filter((f) => fingerprint[f.field])
    .map((f) => ({
      hash_key: `${f.prefix}${fingerprint[f.field]}`,
      device_id: deviceId,
      fuzzy_hash: fuzzyHash,
      ttl,
    }));
}

/**
 * Build all Tier 1 index entries (both identity and hash)
 * @param deviceId - The device ID to index
 * @param fingerprint - The fingerprint containing index values
 * @param ttl - TTL timestamp for DynamoDB expiration
 * @returns Array of all index entries to write
 */
export function buildTier1IndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  return buildIndexEntries(deviceId, fingerprint, ttl);
}

/**
 * Build identity index entries only (evercookie, sigint, public key)
 * @param deviceId - The device ID to index
 * @param fingerprint - The fingerprint containing identity values
 * @param ttl - TTL timestamp for DynamoDB expiration
 * @returns Array of identity index entries to write
 */
export function buildIdentityIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  return buildIndexEntries(deviceId, fingerprint, ttl, "identity");
}

/**
 * Build hash index entries only (stable hash, fuzzy hash)
 * @param deviceId - The device ID to index
 * @param fingerprint - The fingerprint containing hash values
 * @param ttl - TTL timestamp for DynamoDB expiration
 * @returns Array of hash index entries to write
 */
export function buildHashIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  return buildIndexEntries(deviceId, fingerprint, ttl, "hash");
}

/**
 * Batch write Tier 1 index entries with retry logic for unprocessed items
 * Uses removeUndefinedValues to handle optional fuzzy_hash
 * @param deps - Dependencies including DynamoDB client and table names
 * @param entries - Index entries to write
 * @param maxRetries - Maximum retry attempts for unprocessed items (default 3)
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
  await batchWriteWithRetry(deps.dynamodb, {
    tableName: deps.tier1IndexTable,
    items,
    entityName: "Tier1 index",
    maxRetries,
  });
}

/**
 * Write anchor bucket entry for ephemeral matching.
 * Used for both session anchors and IP+UA anchors.
 * Stores created_at for application-side validity check.
 * Uses SESSION_ANCHOR_CLEANUP_TTL for DynamoDB TTL cleanup.
 * @param deps - Dependencies including DynamoDB client and table names
 * @param bucketKey - The anchor bucket key
 * @param deviceId - The device ID to anchor
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
  bucket_key: string;
  device_id: string;
  fuzzy_hash: string;
  last_seen: number;
  ttl: number;
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
 * @param deps - Dependencies including DynamoDB client and table names
 * @param entries - SimHash band entries to write
 * @param maxRetries - Maximum retry attempts for unprocessed items (default 3)
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
  await batchWriteWithRetry(deps.dynamodb, {
    tableName: deps.tier2BucketsTable,
    items,
    entityName: "SimHash band",
    maxRetries,
  });
}
