import { getAwsSecrets } from "./get-aws-secrets";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { MiddlewareObj } from "@middy/core";
import { LRUCache } from "lru-cache";
import { Logger } from "@aws-lambda-powertools/logger";
import { DEDUPE_CACHE_MAX_ENTRIES, DEDUPE_CACHE_TTL_MS } from "./constants";
import { fnv1a } from "./hash";
import { HttpError } from "./http-error";

// Re-export fnv1a for backward compatibility
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

const cache = new LRUCache<string, number>({
  max: DEDUPE_CACHE_MAX_ENTRIES,
  ttl: DEDUPE_CACHE_TTL_MS,
});

export const _clearDeduplicateCache = (): void => {
  cache.clear();
};

/**
 * Deduplicate middleware using LRU cache.
 * Prevents duplicate requests from network retries.
 */
export const deduplicateMiddleware = (): MiddlewareObj<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
> => {
  return {
    before: (request) => {
      const { event } = request;

      if (!event.body) return;

      const key = fnv1a(event.body);

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
