// src/helpers/middy-helpers.ts
import { getAwsSecrets } from "../services/get-aws-secrets";
import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { MiddlewareObj } from "@middy/core";
import { LRUCache } from "lru-cache";
import { Logger } from "@aws-lambda-powertools/logger";
import createError from "http-errors";
import {
  FNV1A_OFFSET_BASIS,
  DEDUPE_CACHE_MAX_ENTRIES,
  DEDUPE_CACHE_TTL_MS,
} from "./constants";

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
 * FNV-1a hash function for fast string hashing
 * Uses standard 32-bit FNV-1a algorithm constants
 */
export const fnv1a = (str: string): string => {
  let hash = FNV1A_OFFSET_BASIS;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash +=
      (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
};

/**
 * Deduplicate middleware using LRU cache
 * Prevents duplicate requests from network retries
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
        throw new createError.TooManyRequests(
          `Duplicate request detected: ${catchCount + 1}`,
        );
      }

      cache.set(key, 1);
    },
  };
};
