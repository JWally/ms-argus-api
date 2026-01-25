/**
 * Payload archiving for analysis and debugging.
 *
 * Samples incoming payloads and archives them to S3 in a partitioned
 * structure for later analysis. Used for model training and debugging.
 * @module
 */
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { gzipSync } from "zlib";

/**
 * Archive a payload to S3 based on sampling rate.
 *
 * Stores payloads in Hive-partitioned format (year/month/day/hour) with
 * gzip compression. Sampling is random based on configured rate.
 * Failures are logged but do not throw to avoid blocking ingestion.
 *
 * @param sessionId - Session ID used as filename
 * @param payload - Payload object to archive
 * @param deps - S3 client, bucket, sample rate, and logging dependencies
 */
export const archivePayload = async (
  sessionId: string,
  payload: unknown,
  deps: {
    s3: S3Client | null;
    bucket: string | undefined;
    sampleRate: number;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<void> => {
  if (!deps.s3 || !deps.bucket || deps.sampleRate <= 0) {
    return;
  }

  if (Math.random() > deps.sampleRate) {
    return;
  }

  try {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    const hour = String(now.getUTCHours()).padStart(2, "0");

    const key = `year=${year}/month=${month}/day=${day}/hour=${hour}/${sessionId}.json.gz`;
    const body = gzipSync(Buffer.from(JSON.stringify(payload)));

    await deps.s3.send(
      new PutObjectCommand({
        Bucket: deps.bucket,
        Key: key,
        Body: body,
        ContentType: "application/json",
        ContentEncoding: "gzip",
      }),
    );

    deps.metrics.addMetric("PayloadArchived", MetricUnit.Count, 1);
  } catch (err) {
    deps.logger.warn("Payload archive failed", {
      error: err,
      session_id: sessionId,
    });
    deps.metrics.addMetric("PayloadArchiveFailed", MetricUnit.Count, 1);
  }
};
