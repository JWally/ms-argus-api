/**
 * @fileoverview Atomic per-merchant credit decrement.
 *
 * Source of truth for "can this merchant make another billable call" is the
 * `credits` column on the merchants Dynamo table (owned by ms-argus-platform).
 * We decrement here on each successful session-get with a conditional
 * UpdateItem; if the condition fails the caller returns 402.
 *
 * @module helpers/credits
 */

import {
  DynamoDBClient,
  UpdateItemCommand,
  ConditionalCheckFailedException,
} from "@aws-sdk/client-dynamodb";

export type DecrementResult =
  | { ok: true; remaining: number }
  | { ok: false; reason: "insufficient_credits" };

export interface DecrementDeps {
  ddb: DynamoDBClient;
  /** Name of the platform's merchants table (env: MERCHANTS_TABLE_NAME). */
  table: string;
}

/**
 * Atomic conditional decrement on `credits`. Succeeds and returns the new
 * balance when `credits >= 1 AND active = true`; otherwise returns
 * `{ ok: false, reason: 'insufficient_credits' }` so the caller can map
 * that to HTTP 402. Concurrent calls serialize at the partition; only one
 * winner per remaining unit.
 */
export async function decrementCredit(
  merchantId: string,
  deps: DecrementDeps,
): Promise<DecrementResult> {
  try {
    const r = await deps.ddb.send(
      new UpdateItemCommand({
        TableName: deps.table,
        Key: { merchantId: { S: merchantId } },
        UpdateExpression: "SET credits = credits - :one",
        ConditionExpression: "credits >= :one AND active = :t",
        ExpressionAttributeValues: {
          ":one": { N: "1" },
          ":t": { BOOL: true },
        },
        ReturnValues: "UPDATED_NEW",
      }),
    );
    const remainingStr = r.Attributes?.credits?.N;
    const remaining = remainingStr ? Number(remainingStr) : 0;
    return { ok: true, remaining };
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      return { ok: false, reason: "insufficient_credits" };
    }
    throw err;
  }
}
