import {
  DynamoDBClient,
  PutItemCommand,
  WriteRequest,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { Fingerprint } from "./types";
import { SESSION_ANCHOR_CLEANUP_TTL_SECONDS } from "../../helpers/constants";
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
 * Type for Tier 1 index entry (identity entries in DynamoDB)
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

const IDENTITY_FIELDS: {
  field: keyof Fingerprint;
  prefix: string;
}[] = [
  { field: "evercookie_id", prefix: "evercookie#" },
  { field: "sigint_id", prefix: "sigint#" },
  { field: "public_key", prefix: "pubkey#" },
];

/**
 * Build identity index entries (evercookie, sigint, public key) for DynamoDB.
 * Hash indexes (stable#, fuzzy#) are now in PostgreSQL device_hashes only.
 */
export function buildIdentityIndexEntries(
  deviceId: string,
  fingerprint: Fingerprint,
  ttl: number,
): Tier1IndexEntry[] {
  const fuzzyHash = fingerprint.fuzzy_hash;
  return IDENTITY_FIELDS.filter((f) => fingerprint[f.field]).map((f) => ({
    hash_key: `${f.prefix}${fingerprint[f.field]}`,
    device_id: deviceId,
    fuzzy_hash: fuzzyHash,
    ttl,
  }));
}

/**
 * Batch write Tier 1 index entries with retry logic for unprocessed items
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
