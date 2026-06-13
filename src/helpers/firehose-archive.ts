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
import {
  FirehoseClient,
  PutRecordCommand,
  DescribeDeliveryStreamCommand,
} from "@aws-sdk/client-firehose";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { boundedRequestHandler } from "./sdk-http-handler";

// Bounded timeouts: this client is touched once per integrity request and sits
// idle the whole inter-request gap, so across a container freeze its socket is
// the one most likely dead on thaw. Without a bound, the dead-socket write
// hangs ~7.5s. See sdk-http-handler.ts.
const firehoseClient = new FirehoseClient({
  requestHandler: boundedRequestHandler,
});

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

/**
 * Keep the Firehose keep-alive socket fresh without writing a record.
 * DescribeDeliveryStream hits the same firehose endpoint as PutRecord, so it
 * exercises the exact socket that would otherwise go stale across a container
 * freeze (see the dead-socket note above). Read-only — nothing is archived.
 * Never throws.
 */
export async function warmFirehose(
  streamName: string | undefined,
): Promise<boolean> {
  if (!streamName) return false;
  try {
    await firehoseClient.send(
      new DescribeDeliveryStreamCommand({ DeliveryStreamName: streamName }),
    );
    return true;
  } catch {
    return false;
  }
}
