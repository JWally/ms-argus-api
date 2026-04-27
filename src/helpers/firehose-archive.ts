/**
 * Firehose archive helper.
 *
 * Fire-and-forget PutRecord into the integrity-archive Firehose stream.
 * The stream batches records and writes gzipped NDJSON to S3 — replacing
 * the per-session DDB stream → Lambda → S3 PUT path. At 1B req/mo this
 * cuts S3 PUT cost from ~$5K/mo to ~$5/mo.
 *
 * Failures are logged + metered but never thrown: the integrity record
 * is already durably stored in DynamoDB, and the response to the client
 * does not depend on the archive succeeding.
 */
import { FirehoseClient, PutRecordCommand } from "@aws-sdk/client-firehose";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";

const firehoseClient = new FirehoseClient({});

/**
 * Send one record to the integrity-archive Firehose stream as
 * newline-terminated JSON. Resolves to true if the put succeeded;
 * false on any error (always swallowed — never throws).
 */
export async function archiveToFirehose(
  item: unknown,
  deps: {
    streamName: string | undefined;
    logger: Logger;
    metrics: Metrics;
    client?: FirehoseClient;
  },
): Promise<boolean> {
  if (!deps.streamName) return false;

  const client = deps.client ?? firehoseClient;
  try {
    await client.send(
      new PutRecordCommand({
        DeliveryStreamName: deps.streamName,
        Record: { Data: Buffer.from(JSON.stringify(item) + "\n") },
      }),
    );
    deps.metrics.addMetric("FirehoseArchived", MetricUnit.Count, 1);
    return true;
  } catch (err) {
    deps.logger.warn("Firehose archive put failed", { error: err });
    deps.metrics.addMetric("FirehoseArchiveFailed", MetricUnit.Count, 1);
    return false;
  }
}
