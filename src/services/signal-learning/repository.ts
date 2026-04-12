/**
 * Signal Baselines Repository
 *
 * Manages the DynamoDB signal-baselines table. Write path: atomic
 * increment of hash counts per browser+module, with automatic locking
 * at a configurable threshold. Read path: cached baseline lookups.
 *
 * Uses LRU cache to avoid DynamoDB calls for already-locked groups
 * on the write path, and for baseline lookups on the read path.
 *
 * @module services/signal-learning/repository
 */

import { LRUCache } from "lru-cache";
import {
  DynamoDBClient,
  UpdateItemCommand,
  GetItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

/** Number of observations before a browser+module group is locked. */
const LOCK_THRESHOLD = 100;

/** Minimum percentage of observations a hash must have to be included in the locked set. */
const MIN_HASH_PERCENT = 0.05;

/** LRU cache for locked state (write path — prevents DDB calls for locked groups). */
const lockCache = new LRUCache<string, boolean>({ max: 1000 });

export interface CachedBaseline {
  locked: boolean;
  lockedHashes: Set<string> | null;
}

/** LRU cache for baseline lookups (read path — 5 min TTL for freshness). */
const baselineCache = new LRUCache<string, CachedBaseline>({
  max: 500,
  ttl: 5 * 60 * 1000,
});

const client = new DynamoDBClient({});

function tableName(): string {
  return process.env.SIGNAL_BASELINES_TABLE ?? "";
}

function cacheKey(browserKey: string, module: string): string {
  return `${browserKey}#${module}`;
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

/**
 * Ensure the baseline item shell exists (idempotent).
 * DynamoDB doesn't allow SET on a map and ADD on a nested key of that map
 * in one expression, so this MUST run before the increment update.
 */
async function ensureBaselineShell(
  browserKey: string,
  module: string,
): Promise<void> {
  await client.send(
    new UpdateItemCommand({
      TableName: tableName(),
      Key: marshall({ browser_key: browserKey, module }),
      UpdateExpression:
        "SET created_at = if_not_exists(created_at, :now), " +
        "hashes = if_not_exists(hashes, :empty_map), " +
        "observed_count = if_not_exists(observed_count, :zero), " +
        "locked = if_not_exists(locked, :false)",
      ExpressionAttributeValues: marshall({
        ":now": Date.now(),
        ":empty_map": {},
        ":zero": 0,
        ":false": false,
      }),
    }),
  );
}

/** Atomic increment of the hash count + total observed_count. */
async function applyIncrement(
  browserKey: string,
  module: string,
  hash: string,
): Promise<Record<string, unknown>> {
  const result = await client.send(
    new UpdateItemCommand({
      TableName: tableName(),
      Key: marshall({ browser_key: browserKey, module }),
      UpdateExpression: "ADD observed_count :one, hashes.#hash :one",
      ConditionExpression: "locked = :false",
      ExpressionAttributeNames: { "#hash": hash },
      ExpressionAttributeValues: marshall({ ":one": 1, ":false": false }),
      ReturnValues: "ALL_NEW",
    }),
  );
  return unmarshall(result.Attributes!);
}

/**
 * Increment the count for a signal hash observation.
 * Skips silently if the group is already locked (from LRU cache or DDB condition).
 */
async function incrementSignal(
  browserKey: string,
  module: string,
  hash: string,
): Promise<void> {
  const key = cacheKey(browserKey, module);
  if (lockCache.get(key)) return;

  try {
    await ensureBaselineShell(browserKey, module);
    const item = await applyIncrement(browserKey, module, hash);
    if (
      typeof item.observed_count === "number" &&
      item.observed_count >= LOCK_THRESHOLD &&
      !item.locked
    ) {
      await lockBaseline(
        browserKey,
        module,
        item.hashes as Record<string, number>,
        item.observed_count,
      );
    }
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      lockCache.set(key, true);
      return;
    }
    throw err;
  }
}

/**
 * Lock a baseline group: compute the set of valid hashes and freeze it.
 * Idempotent — conditional expression ensures only one lock succeeds.
 */
async function lockBaseline(
  browserKey: string,
  module: string,
  hashes: Record<string, number>,
  totalCount: number,
): Promise<void> {
  const threshold = totalCount * MIN_HASH_PERCENT;
  const lockedHashes = Object.entries(hashes)
    .filter(([, count]) => count >= threshold)
    .map(([hash]) => hash);

  if (lockedHashes.length === 0) return;

  try {
    await client.send(
      new UpdateItemCommand({
        TableName: tableName(),
        Key: marshall({ browser_key: browserKey, module }),
        UpdateExpression:
          "SET locked = :true, locked_hashes = :hashes, locked_at = :now",
        ConditionExpression: "locked = :false",
        ExpressionAttributeValues: marshall({
          ":true": true,
          ":hashes": new Set(lockedHashes),
          ":now": Date.now(),
          ":false": false,
        }),
      }),
    );
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      // Already locked by another invocation — that's fine
    } else {
      throw err;
    }
  }

  // Update caches
  const key = cacheKey(browserKey, module);
  lockCache.set(key, true);
  baselineCache.set(key, {
    locked: true,
    lockedHashes: new Set(lockedHashes),
  });
}

// ---------------------------------------------------------------------------
// Read path
// ---------------------------------------------------------------------------

/**
 * Get the baseline for a browser+module combo.
 * Returns from LRU cache if available, otherwise reads from DynamoDB.
 */
export async function getBaseline(
  browserKey: string,
  module: string,
): Promise<CachedBaseline> {
  const key = cacheKey(browserKey, module);
  const cached = baselineCache.get(key);
  if (cached !== undefined) return cached;

  const result = await client.send(
    new GetItemCommand({
      TableName: tableName(),
      Key: marshall({ browser_key: browserKey, module }),
      ProjectionExpression: "locked, locked_hashes",
    }),
  );

  if (!result.Item) {
    const entry: CachedBaseline = { locked: false, lockedHashes: null };
    baselineCache.set(key, entry);
    return entry;
  }

  const item = unmarshall(result.Item);
  const entry: CachedBaseline = {
    locked: item.locked === true,
    lockedHashes: item.locked_hashes
      ? new Set(item.locked_hashes as string[])
      : null,
  };
  baselineCache.set(key, entry);

  // Also update write-path lock cache
  if (entry.locked) lockCache.set(key, true);

  return entry;
}

/**
 * Batch-fetch baselines for all signal modules for a browser key.
 * Used by the anomaly detector read path.
 */
export async function getBaselines(
  browserKey: string,
  modules: string[],
): Promise<Map<string, CachedBaseline>> {
  const result = new Map<string, CachedBaseline>();
  await Promise.all(
    modules.map(async (mod) => {
      result.set(mod, await getBaseline(browserKey, mod));
    }),
  );
  return result;
}

/** Signal module names tracked by the learning system. */
export const SIGNAL_MODULES = [
  "math",
  "eval_length",
  "css_key_count",
  "window_moz",
  "worker_nav_props",
];

/**
 * Learn signal observations: increment counts for each signal.
 * Fire-and-forget — callers should catch errors.
 */
export async function learnSignals(observation: {
  browserKey: string;
  signals: Array<{ module: string; hash: string }>;
}): Promise<void> {
  await Promise.all(
    observation.signals.map((s) =>
      incrementSignal(observation.browserKey, s.module, s.hash),
    ),
  );
}
