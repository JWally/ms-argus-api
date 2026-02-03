/**
 * Admin Lambda to flush the statistical v2 cache.
 *
 * Invoke via AWS CLI:
 *   aws lambda invoke --function-name <stack>-FlushCache --payload '{"confirm": true}' out.json
 *
 * Or from AWS Console > Lambda > Test with payload: {"confirm": true}
 *
 * DANGER: This clears all statistical baselines, requiring re-learning.
 */

import { Logger } from "@aws-lambda-powertools/logger";
import Redis from "ioredis";

const logger = new Logger({ serviceName: "flush-cache" });

interface FlushEvent {
  confirm?: boolean;
  pattern?: string; // Optional: only flush keys matching pattern
}

interface FlushResult {
  success: boolean;
  message: string;
  keysDeleted?: number;
}

export async function handler(event: FlushEvent): Promise<FlushResult> {
  logger.info("Flush cache invoked", { event });

  // Safety check
  if (!event.confirm) {
    return {
      success: false,
      message: 'Must pass {"confirm": true} to flush cache',
    };
  }

  const endpoint = process.env.VALKEY_ENDPOINT;
  if (!endpoint) {
    return {
      success: false,
      message: "VALKEY_ENDPOINT not configured",
    };
  }

  const client = new Redis({
    host: endpoint,
    port: 6379,
    tls: {},
    connectTimeout: 5000,
  });

  try {
    // Default pattern: flush all stat:v2: keys
    const pattern = event.pattern || "stat:v2:*";

    logger.info("Scanning for keys", { pattern });

    // Use SCAN to find matching keys (safer than KEYS for large datasets)
    let cursor = "0";
    let totalDeleted = 0;

    do {
      const [nextCursor, keys] = await client.scan(
        cursor,
        "MATCH",
        pattern,
        "COUNT",
        1000,
      );
      cursor = nextCursor;

      if (keys.length > 0) {
        await client.del(...keys);
        totalDeleted += keys.length;
        logger.info("Deleted batch", {
          count: keys.length,
          total: totalDeleted,
        });
      }
    } while (cursor !== "0");

    logger.info("Cache flush complete", { totalDeleted, pattern });

    return {
      success: true,
      message: `Flushed ${totalDeleted} keys matching ${pattern}`,
      keysDeleted: totalDeleted,
    };
  } catch (error) {
    logger.error("Cache flush failed", { error });
    return {
      success: false,
      message: `Error: ${String(error)}`,
    };
  } finally {
    await client.quit();
  }
}
