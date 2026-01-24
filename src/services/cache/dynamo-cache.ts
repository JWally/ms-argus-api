import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";
import { SessionCacheValue } from "../../types";

export interface DynamoCacheConfig {
  tableName: string;
  sessionTtlSeconds: number;
  mutationGateTtlSeconds: number;
}

/**
 * DynamoDB-based session cache service
 *
 * Replaces Redis for session caching with several benefits:
 * - Zero idle cost (pay per request vs fixed Redis instance)
 * - No VPC required (simplifies infrastructure)
 * - Built-in TTL expiration (DynamoDB TTL feature)
 * - Simpler operational model (one less service to manage)
 *
 * Cache key patterns:
 * - session:{session_id} - Session cache entries
 * - gate:{device_id} - Mutation gates for write coalescing
 */
export class DynamoCacheService {
  constructor(
    private readonly dynamodb: DynamoDBClient,
    private readonly config: DynamoCacheConfig,
  ) {}

  /**
   * Check if a session result is cached
   * Returns null if not found or expired
   */
  async checkSessionCache(
    sessionId: string,
  ): Promise<SessionCacheValue | null> {
    const key = `session:${sessionId}`;

    const result = await this.dynamodb.send(
      new GetItemCommand({
        TableName: this.config.tableName,
        Key: marshall({ cache_key: key }),
      }),
    );

    if (!result.Item) {
      return null;
    }

    const item = unmarshall(result.Item);

    // Check TTL (DynamoDB TTL is eventually consistent, check ourselves)
    const now = Math.floor(Date.now() / 1000);
    if (item.ttl && item.ttl < now) {
      return null;
    }

    return item.value as SessionCacheValue;
  }

  /**
   * Write session result to cache
   * Uses conditional write to only update if confidence is higher
   *
   * @returns true if written, false if skipped (existing has higher confidence)
   */
  async writeSessionCache(
    sessionId: string,
    value: SessionCacheValue,
  ): Promise<boolean> {
    const key = `session:${sessionId}`;
    const ttl = Math.floor(Date.now() / 1000) + this.config.sessionTtlSeconds;

    try {
      await this.dynamodb.send(
        new PutItemCommand({
          TableName: this.config.tableName,
          Item: marshall(
            {
              cache_key: key,
              value,
              confidence: value.confidence,
              ttl,
            },
            { removeUndefinedValues: true },
          ),
          // Only write if: key doesn't exist OR new confidence > existing
          ConditionExpression:
            "attribute_not_exists(cache_key) OR confidence < :conf",
          ExpressionAttributeValues: marshall({ ":conf": value.confidence }),
        }),
      );
      return true;
    } catch (error) {
      // ConditionalCheckFailedException means existing value has higher confidence
      // This is expected behavior, not an error - return false to indicate write was skipped
      if (error instanceof ConditionalCheckFailedException) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Try to acquire a mutation gate for a device
   * Returns true if acquired, false if gate already exists
   *
   * Used to coalesce rapid writes to the same device profile
   */
  async tryAcquireMutationGate(deviceId: string): Promise<boolean> {
    const key = `gate:${deviceId}`;
    const ttl =
      Math.floor(Date.now() / 1000) + this.config.mutationGateTtlSeconds;

    try {
      await this.dynamodb.send(
        new PutItemCommand({
          TableName: this.config.tableName,
          Item: marshall({
            cache_key: key,
            ttl,
          }),
          // Only succeed if key doesn't exist
          ConditionExpression: "attribute_not_exists(cache_key)",
        }),
      );
      return true;
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        return false; // Gate already exists
      }
      throw error;
    }
  }
}
