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

import { DynamoDBStreamHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import type { AttributeValue } from "@aws-sdk/client-dynamodb";
import { getIntegrityArchiverEnv } from "../config/env";

const envConfig = getIntegrityArchiverEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const s3 = new S3Client({});

export const handler: DynamoDBStreamHandler = async (event) => {
  let archived = 0;
  let errors = 0;

  for (const record of event.Records) {
    if (record.eventName !== "INSERT") continue;

    const image = record.dynamodb?.NewImage;
    if (!image) continue;

    const item = unmarshall(image as Record<string, AttributeValue>);
    const sessionId = item.session_id as string;
    if (!sessionId) {
      logger.warn("Missing session_id in stream record", {
        eventID: record.eventID,
      });
      continue;
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
      archived++;
    } catch (err) {
      logger.error("Failed to archive integrity result", {
        error: err,
        session_id: sessionId,
        key,
      });
      errors++;
    }
  }

  metrics.addMetric("IntegrityArchived", MetricUnit.Count, archived);
  if (errors > 0) {
    metrics.addMetric("IntegrityArchiveErrors", MetricUnit.Count, errors);
  }
  metrics.publishStoredMetrics();

  logger.info("Integrity archive batch complete", { archived, errors });
};
