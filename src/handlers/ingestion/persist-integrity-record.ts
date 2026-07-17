import type { Logger } from "@aws-lambda-powertools/logger";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import { MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  ConditionalCheckFailedException,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";
import { archiveToFirehose } from "../../helpers/firehose-archive";
import { HttpError } from "../../helpers/http-error";

interface DynamoSender {
  send(command: PutItemCommand): Promise<unknown>;
}

export interface PersistIntegrityRecordContext {
  cpi: string;
  sessionId: string;
  deps: {
    logger: Logger;
    metrics: Metrics;
  };
}

export interface PersistIntegrityRecordDeps {
  dynamo: DynamoSender;
  tableName: string;
  firehoseStreamName?: string;
}

/**
 * Persist the integrity record to the durable DynamoDB source of truth while
 * starting best-effort Firehose archival without holding the client response.
 *
 * A conditional-write collision is an idempotent retry of the same
 * `(cpi, session_id)`, not a distinct replay. The existing row is never
 * overwritten, and the caller can safely return the original session ID.
 */
export async function persistIntegrityRecord(
  ctx: PersistIntegrityRecordContext,
  item: Record<string, unknown>,
  deps: PersistIntegrityRecordDeps,
): Promise<{ duplicate: boolean }> {
  void archiveToFirehose(item, {
    streamName: deps.firehoseStreamName,
    logger: ctx.deps.logger,
    metrics: ctx.deps.metrics,
  }).catch(() => {});

  try {
    await deps.dynamo.send(
      new PutItemCommand({
        TableName: deps.tableName,
        Item: marshall(item, { removeUndefinedValues: true }),
        ConditionExpression: "attribute_not_exists(cpi)",
      }),
    );
    return { duplicate: false };
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      ctx.deps.metrics.addMetric(
        "IntegrityIdempotentRetry",
        MetricUnit.Count,
        1,
      );
      ctx.deps.logger.info(
        "integrity same-session retry — returning existing session",
        { cpi: ctx.cpi, session_id: ctx.sessionId },
      );
      return { duplicate: true };
    }
    ctx.deps.logger.error("Integrity DynamoDB write failed", {
      error: err,
      cpi: ctx.cpi,
      session_id: ctx.sessionId,
    });
    ctx.deps.metrics.addMetric("IntegrityWriteFailed", MetricUnit.Count, 1);
    throw new HttpError(503, "Service temporarily unavailable");
  }
}
