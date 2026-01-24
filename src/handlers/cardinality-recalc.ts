// Fixes drift from TTL-expired devices (ADD only increments, never decrements)
import { ScheduledHandler } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { validateRequiredEnvVars } from "../helpers/env-validation";
import {
  processAllBuckets,
  emitRecalcMetrics,
} from "./cardinality-recalc/orchestrator";

interface CardinalityRecalcEnvConfig {
  TIER2_BUCKETS_TABLE: string;
  POWERTOOLS_SERVICE_NAME: string;
  POWERTOOLS_METRICS_NAMESPACE: string;
}

function getCardinalityRecalcEnv(): CardinalityRecalcEnvConfig {
  validateRequiredEnvVars(["TIER2_BUCKETS_TABLE"]);

  return {
    TIER2_BUCKETS_TABLE: process.env.TIER2_BUCKETS_TABLE!,
    POWERTOOLS_SERVICE_NAME:
      process.env.POWERTOOLS_SERVICE_NAME || "argus-cardinality-recalc",
    POWERTOOLS_METRICS_NAMESPACE:
      process.env.POWERTOOLS_METRICS_NAMESPACE || "Argus",
  };
}

const envConfig: CardinalityRecalcEnvConfig = getCardinalityRecalcEnv();

const logger = new Logger({ serviceName: envConfig.POWERTOOLS_SERVICE_NAME });
const metrics = new Metrics({
  namespace: envConfig.POWERTOOLS_METRICS_NAMESPACE,
});

const dynamodb = new DynamoDBClient({});

/** Cardinality Recalculation Lambda Handler - triggered daily via EventBridge */
export const handler: ScheduledHandler = async (event): Promise<void> => {
  const startTime = Date.now();
  const tableName = envConfig.TIER2_BUCKETS_TABLE;

  logger.info("Starting cardinality recalculation", {
    tableName,
    eventSource: event.source,
  });

  const ttl = Math.floor(Date.now() / 1000) + 14 * 24 * 60 * 60;
  try {
    const stats = await processAllBuckets(tableName, ttl, { dynamodb, logger });
    emitRecalcMetrics(stats, Date.now() - startTime, { metrics, logger });
  } finally {
    metrics.publishStoredMetrics();
  }
};
