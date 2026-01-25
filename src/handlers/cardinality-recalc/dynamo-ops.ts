/**
 * @fileoverview DynamoDB operations for cardinality recalculation.
 * Provides scanning, counting, and updating operations for Tier2 bucket statistics.
 * @module handlers/cardinality-recalc/dynamo-ops
 */

import { Logger } from "@aws-lambda-powertools/logger";
import {
  DynamoDBClient,
  ScanCommand,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { TIER2_STATS_SK } from "../../helpers/constants";

/**
 * Async generator that scans all unique bucket keys from the Tier2 buckets table.
 *
 * Yields pages of bucket keys to allow incremental processing without loading
 * the entire dataset into memory. Each page contains a Set of unique bucket_key
 * values found in that scan segment.
 *
 * @param tableName - DynamoDB table name to scan
 * @param deps - Dependencies for database access and logging
 * @param deps.dynamodb - DynamoDB client instance
 * @param deps.logger - Logger for debug output on scan progress
 * @yields Set of bucket keys for each scan page
 *
 * @example
 * ```typescript
 * for await (const pageKeys of scanBucketKeysPages(tableName, deps)) {
 *   for (const bucketKey of pageKeys) {
 *     await processBucket(bucketKey);
 *   }
 * }
 * ```
 */
export async function* scanBucketKeysPages(
  tableName: string,
  deps: { dynamodb: DynamoDBClient; logger: Logger },
): AsyncGenerator<Set<string>, void, undefined> {
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  let pageNumber = 0;

  do {
    pageNumber++;
    const response = await deps.dynamodb.send(
      new ScanCommand({
        TableName: tableName,
        ProjectionExpression: "bucket_key",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    const pageKeys = new Set<string>();
    for (const item of response.Items || []) {
      if (item.bucket_key?.S) {
        pageKeys.add(item.bucket_key.S);
      }
    }

    deps.logger.debug("Scanned bucket keys page", {
      pageNumber,
      keysInPage: pageKeys.size,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    yield pageKeys;

    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);
}

/**
 * Counts the number of device entries in a Tier2 bucket.
 *
 * Queries all items with the given bucket_key, filtering out the stats item
 * (identified by TIER2_STATS_SK). Uses pagination to count buckets with more
 * than 1MB of data.
 *
 * @param tableName - DynamoDB table name
 * @param bucketKey - Partition key of the bucket to count
 * @param dynamodb - DynamoDB client instance
 * @returns Total count of device entries in the bucket
 *
 * @example
 * ```typescript
 * const deviceCount = await countBucketDevices(tableName, "ua#Chrome/120#1920x1080", dynamodb);
 * console.log(`Bucket contains ${deviceCount} devices`);
 * ```
 */
export async function countBucketDevices(
  tableName: string,
  bucketKey: string,
  dynamodb: DynamoDBClient,
): Promise<number> {
  let count = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const response = await dynamodb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: "bucket_key = :pk",
        FilterExpression: "device_id <> :stats_sk",
        ExpressionAttributeValues: {
          ":pk": { S: bucketKey },
          ":stats_sk": { S: TIER2_STATS_SK },
        },
        Select: "COUNT",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    count += response.Count || 0;
    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);

  return count;
}

/**
 * Retrieves the currently stored cardinality for a bucket.
 *
 * Reads the _stats item for the bucket and extracts the cardinality value.
 * Returns 0 if no stats item exists (new bucket).
 *
 * @param tableName - DynamoDB table name
 * @param bucketKey - Partition key of the bucket
 * @param dynamodb - DynamoDB client instance
 * @returns Current cardinality value, or 0 if not yet computed
 *
 * @example
 * ```typescript
 * const current = await getCurrentCardinality(tableName, bucketKey, dynamodb);
 * const actual = await countBucketDevices(tableName, bucketKey, dynamodb);
 * if (current !== actual) {
 *   await updateCardinality({ tableName, bucketKey, cardinality: actual, ttl }, dynamodb);
 * }
 * ```
 */
export async function getCurrentCardinality(
  tableName: string,
  bucketKey: string,
  dynamodb: DynamoDBClient,
): Promise<number> {
  const response = await dynamodb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: "bucket_key = :pk AND device_id = :sk",
      ExpressionAttributeValues: {
        ":pk": { S: bucketKey },
        ":sk": { S: TIER2_STATS_SK },
      },
      ProjectionExpression: "cardinality",
    }),
  );

  const item = response.Items?.[0];
  if (item?.cardinality?.N) {
    return parseInt(item.cardinality.N, 10);
  }
  return 0;
}

/**
 * Updates the cardinality value in a bucket's stats item.
 *
 * Creates or updates the _stats item with the new cardinality count and TTL.
 * The TTL ensures stale stats are eventually cleaned up if a bucket becomes
 * inactive.
 *
 * @param params - Update parameters
 * @param params.tableName - DynamoDB table name
 * @param params.bucketKey - Partition key of the bucket
 * @param params.cardinality - New cardinality value to store
 * @param params.ttl - Unix timestamp for DynamoDB TTL cleanup
 * @param dynamodb - DynamoDB client instance
 *
 * @example
 * ```typescript
 * const ttl = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60); // 7 days
 * await updateCardinality({ tableName, bucketKey, cardinality: 42, ttl }, dynamodb);
 * ```
 */
export async function updateCardinality(
  params: {
    tableName: string;
    bucketKey: string;
    cardinality: number;
    ttl: number;
  },
  dynamodb: DynamoDBClient,
): Promise<void> {
  const { tableName, bucketKey, cardinality, ttl } = params;
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: tableName,
      Key: {
        bucket_key: { S: bucketKey },
        device_id: { S: TIER2_STATS_SK },
      },
      UpdateExpression: "SET cardinality = :c, #ttl = :ttl",
      ExpressionAttributeNames: {
        "#ttl": "ttl",
      },
      ExpressionAttributeValues: {
        ":c": { N: String(cardinality) },
        ":ttl": { N: String(ttl) },
      },
    }),
  );
}
