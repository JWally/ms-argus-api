/**
 * @fileoverview Integrity Archiver Lambda Handler.
 *
 * Triggered by DynamoDB Streams on the integrity-results table.
 * Writes each new integrity result to S3 as individual JSON files
 * for later analysis. Files auto-expire after 14 days via bucket lifecycle.
 *
 * S3 key format: {sessionId}.json
 *
 * @module handlers/integrity-archiver
 */

import type { DynamoDBStreamEvent, DynamoDBRecord } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import middy from "@middy/core";
import warmup from "@middy/warmup";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { getIntegrityArchiverEnv } from "../config/env";
import { onWarmup } from "../helpers/middy-helpers";

const envConfig = getIntegrityArchiverEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const s3 = new S3Client({});

type ArchiveOutcome = "archived" | "skipped" | "error";

/** Process one DynamoDB stream record; returns the outcome for metrics. */
async function archiveRecord(record: DynamoDBRecord): Promise<ArchiveOutcome> {
  if (record.eventName !== "INSERT") return "skipped";

  const image = record.dynamodb?.NewImage;
  if (!image) return "skipped";

  const item = unmarshall(image as Record<string, AttributeValue>);
  const sessionId = item.session_id as string;
  if (!sessionId) {
    logger.warn("Missing session_id in stream record", {
      eventID: record.eventID,
    });
    return "skipped";
  }

  const key = `${sessionId}.json`;
  try {
    await s3.send(
      new PutObjectCommand({
        Bucket: envConfig.INTEGRITY_ARCHIVE_BUCKET,
        Key: key,
        Body: JSON.stringify(item),
        ContentType: "application/json",
      }),
    );
    return "archived";
  } catch (err) {
    logger.error("Failed to archive integrity result", {
      error: err,
      session_id: sessionId,
      key,
    });
    return "error";
  }
}

// Warmup events come from EventBridge with `{ warmup: true, source: "warmup-rule" }`.
// They do NOT have `.Records`, so a typeguard protects the stream path from
// pings that middy's warmup middleware doesn't short-circuit (e.g. tests).
const baseHandler = async (
  event: DynamoDBStreamEvent | { warmup?: boolean },
): Promise<void> => {
  if (!("Records" in event) || !Array.isArray(event.Records)) {
    logger.info("Non-stream event ignored (likely warmup)");
    return;
  }

  let archived = 0;
  let errors = 0;
  for (const record of event.Records) {
    const outcome = await archiveRecord(record);
    if (outcome === "archived") archived++;
    else if (outcome === "error") errors++;
  }

  metrics.addMetric("IntegrityArchived", MetricUnit.Count, archived);
  if (errors > 0) {
    metrics.addMetric("IntegrityArchiveErrors", MetricUnit.Count, errors);
  }
  metrics.publishStoredMetrics();

  logger.info("Integrity archive batch complete", { archived, errors });
};

export const handler = middy(baseHandler).use(warmup({ onWarmup }));
