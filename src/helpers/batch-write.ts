import {
  DynamoDBClient,
  BatchWriteItemCommand,
  WriteRequest,
} from "@aws-sdk/client-dynamodb";
import { sleep } from "./sleep";

/**
 * Parameters for batch write with retry
 */
export interface BatchWriteParams {
  /** DynamoDB table name */
  tableName: string;
  /** Array of write requests to execute */
  items: WriteRequest[];
  /** Entity name for error messages */
  entityName: string;
  /** Maximum retry attempts (default 3) */
  maxRetries?: number;
}

/**
 * Batch write to DynamoDB with exponential backoff retry for unprocessed items.
 * @param client - DynamoDB client instance
 * @param params - Batch write parameters
 * @throws Error if items remain unprocessed after max retries
 */
export async function batchWriteWithRetry(
  client: DynamoDBClient,
  params: BatchWriteParams,
): Promise<void> {
  const { tableName, items, entityName, maxRetries = 3 } = params;
  if (items.length === 0) return;

  let unprocessedItems = items;
  let attempt = 0;

  while (unprocessedItems.length > 0 && attempt < maxRetries) {
    const result = await client.send(
      new BatchWriteItemCommand({
        RequestItems: {
          [tableName]: unprocessedItems,
        },
      }),
    );

    const remaining = result.UnprocessedItems?.[tableName];
    if (remaining && remaining.length > 0) {
      unprocessedItems = remaining;
      attempt++;
      await sleep(Math.pow(2, attempt) * 100);
    } else {
      unprocessedItems = [];
    }
  }

  if (unprocessedItems.length > 0) {
    throw new Error(
      `Failed to write ${unprocessedItems.length} ${entityName} items after ${maxRetries} retries`,
    );
  }
}
