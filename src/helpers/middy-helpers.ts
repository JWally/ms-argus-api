// src/helpers/middy-helpers.ts
import { getAwsSecrets } from "../services/get-aws-secrets";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { MiddlewareObj } from "@middy/core";
import { LRUCache } from "lru-cache";
import { Logger } from "@aws-lambda-powertools/logger";
import { DEDUPE_CACHE_MAX_ENTRIES, DEDUPE_CACHE_TTL_MS } from "./constants";
import { fnv1a } from "./hash";

// Custom HttpError class to replace http-errors module (ESM bundling compatible)
class HttpError extends Error {
  statusCode: number;
  expose: boolean;
  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.expose = statusCode < 500;
  }
}

// Re-export fnv1a for backward compatibility (AR-32)
export { fnv1a };

const logger = new Logger({ serviceName: "argus-warmup" });

interface MiddyEvent {
  source: string;
  warmup?: boolean;
}

export const isWarmingUp = (event: MiddyEvent) => {
  return (
    event.source === "serverless-plugin-warmup" ||
    event.source === "warmup-plugin" ||
    event?.warmup === true
  );
};

export const onWarmup = async () => {
  try {
    await getAwsSecrets();
    logger.info("Warmup completed successfully");
  } catch (error) {
    logger.error("Warmup failed", { error });
  }
};

// Global LRU cache for deduplication
const cache = new LRUCache<string, number>({
  max: DEDUPE_CACHE_MAX_ENTRIES,
  ttl: DEDUPE_CACHE_TTL_MS,
});

export const _clearDeduplicateCache = (): void => {
  cache.clear();
};

/**
 * Deduplicate middleware using LRU cache
 * Prevents duplicate requests from network retries
 * AR-97: Key now includes tenant ID to isolate deduplication per tenant
 */
export const deduplicateMiddleware = (): MiddlewareObj<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
> => {
  return {
    before: (request) => {
      const { event } = request;

      if (!event.body) return;

      // AR-97: Include tenant ID in cache key to isolate deduplication per tenant
      const tenantId = event.headers["x-tenant-id"] ?? "default";
      const key = fnv1a(`${tenantId}:${event.body}`);

      if (cache.has(key)) {
        const catchCount: number = cache.get(key) || 0;
        cache.set(key, 1 + catchCount);
        throw new HttpError(
          429,
          `Duplicate request detected: ${catchCount + 1}`,
        );
      }

      cache.set(key, 1);
    },
  };
};
