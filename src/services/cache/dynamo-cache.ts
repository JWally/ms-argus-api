// src/services/cache/dynamo-cache.ts
// Replaces Redis with DynamoDB for session caching and mutation gates
// Benefits: zero idle cost, no VPC requirements, simpler infrastructure

import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { SessionCacheValue } from "../../types";

/**
 * Configuration for the DynamoDB cache service
 */
export interface DynamoCacheConfig {
  tableName: string;
  sessionTtlSeconds: number;
  mutationGateTtlSeconds: number;
}

/**
 * DynamoDB-based cache service
 * Replaces Redis for session caching and mutation gates
 *
 * Key patterns:
 * - Session cache: "session:{sessionId}"
 * - Mutation gate: "gate:{deviceId}"
 */
export class DynamoCacheService {
  constructor(
    private dynamodb: DynamoDBClient,
    private config: DynamoCacheConfig,
  ) {}

  /**
   * Check if session result is cached
   * @param sessionId Session identifier
   * @returns Cached session value or null if not found/expired
   */
  async checkSessionCache(
    sessionId: string,
  ): Promise<SessionCacheValue | null> {
    const result = await this.dynamodb.send(
      new GetItemCommand({
        TableName: this.config.tableName,
        Key: marshall({ cache_key: `session:${sessionId}` }),
      }),
    );

    if (!result.Item) {
      return null;
    }

    const item = unmarshall(result.Item);

    // Check if TTL has expired (DynamoDB TTL deletion is eventually consistent)
    if (item.ttl && item.ttl < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return item.value as SessionCacheValue;
  }

  /**
   * Write session result to cache
   * Uses conditional write to preserve better matches (higher confidence)
   *
   * @param sessionId Session identifier
   * @param value Session cache value
   */
  async writeSessionCache(
    sessionId: string,
    value: SessionCacheValue,
  ): Promise<void> {
    const cacheKey = `session:${sessionId}`;
    const ttl = Math.floor(Date.now() / 1000) + this.config.sessionTtlSeconds;

    try {
      await this.dynamodb.send(
        new PutItemCommand({
          TableName: this.config.tableName,
          Item: marshall({
            cache_key: cacheKey,
            value,
            confidence: value.confidence,
            ttl,
          }),
          // Only write if:
          // 1. Key doesn't exist, OR
          // 2. Existing confidence is lower than new confidence, OR
          // 3. Existing status is "degraded" (always overwrite degraded)
          ConditionExpression:
            "attribute_not_exists(cache_key) OR confidence < :newConfidence OR #status = :degraded",
          ExpressionAttributeNames: {
            "#status": "value.status",
          },
          ExpressionAttributeValues: marshall({
            ":newConfidence": value.confidence,
            ":degraded": "degraded",
          }),
        }),
      );
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        // Existing result has higher confidence, skip write
        return;
      }
      throw error;
    }
  }

  /**
   * Atomically try to acquire mutation gate for a device
   * Prevents rapid repeated writes to DynamoDB profiles
   *
   * Uses conditional write (attribute_not_exists) for atomicity
   * Similar to Redis SET NX EX pattern
   *
   * @param deviceId Device identifier
   * @returns true if gate acquired, false if already held
   */
  async tryAcquireMutationGate(deviceId: string): Promise<boolean> {
    const cacheKey = `gate:${deviceId}`;
    const ttl =
      Math.floor(Date.now() / 1000) + this.config.mutationGateTtlSeconds;

    try {
      await this.dynamodb.send(
        new PutItemCommand({
          TableName: this.config.tableName,
          Item: marshall({
            cache_key: cacheKey,
            acquired_at: Date.now(),
            ttl,
          }),
          // Only succeed if key doesn't exist (atomic compare-and-set)
          ConditionExpression: "attribute_not_exists(cache_key)",
        }),
      );
      return true;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        // Gate already held by another invocation
        return false;
      }
      throw error;
    }
  }
}
