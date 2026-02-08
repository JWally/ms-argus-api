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
 * Structural hash keys that indicate a high-quality payload.
 * Skinny test payloads are missing these.
 */
const STRUCTURAL_HASH_KEYS = [
  "maths",
  "windowFeatures",
  "htmlElementVersion",
  "css",
  "svg",
  "intl",
  "features",
  "clientRects",
  "consoleErrors",
];

/**
 * Check if a raw payload has sufficient quality for long-term retention.
 * Skinny payloads (from automation tests) lack structural hashes.
 */
function isHighQualityPayload(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;

  const p = payload as Record<string, unknown>;

  // Check for hashes object with structural keys
  const hashes = p.hashes as Record<string, unknown> | undefined;
  if (!hashes) return false;

  // Count structural hashes present
  const structuralCount = STRUCTURAL_HASH_KEYS.filter(
    (key) => typeof hashes[key] === "string" && hashes[key],
  ).length;

  // Require at least 3 structural hashes for high quality
  return structuralCount >= 3;
}

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
/** Build a Hive-partitioned S3 key from the current UTC time. */
function buildArchiveKey(sessionId: string): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const h = String(now.getUTCHours()).padStart(2, "0");
  return `year=${y}/month=${m}/day=${d}/hour=${h}/${sessionId}.json.gz`;
}

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
  if (!deps.s3 || !deps.bucket || deps.sampleRate <= 0) return;
  if (Math.random() > deps.sampleRate) return;

  try {
    const body = gzipSync(Buffer.from(JSON.stringify(payload)));
    const highQuality = isHighQualityPayload(payload);

    await deps.s3.send(
      new PutObjectCommand({
        Bucket: deps.bucket,
        Key: buildArchiveKey(sessionId),
        Body: body,
        ContentType: "application/json",
        ContentEncoding: "gzip",
        Tagging: `quality=${highQuality ? "high" : "low"}`,
      }),
    );

    deps.metrics.addMetric("PayloadArchived", MetricUnit.Count, 1);
    deps.metrics.addMetric(
      highQuality ? "PayloadArchivedHighQuality" : "PayloadArchivedLowQuality",
      MetricUnit.Count,
      1,
    );
  } catch (err) {
    deps.logger.warn("Payload archive failed", {
      error: err,
      session_id: sessionId,
    });
    deps.metrics.addMetric("PayloadArchiveFailed", MetricUnit.Count, 1);
  }
};
