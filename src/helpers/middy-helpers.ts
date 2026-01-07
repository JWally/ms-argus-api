// src/helpers/middy-helpers.ts
import { getAwsSecrets } from '../services/get-aws-secrets';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { MiddlewareObj } from '@middy/core';
import { LRUCache } from 'lru-cache';
import createError from 'http-errors';

interface MiddyEvent {
  source: string;
  warmup?: boolean;
}

export const isWarmingUp = (event: MiddyEvent) => {
  return (
    event.source === 'serverless-plugin-warmup' ||
    event.source === 'warmup-plugin' ||
    event?.warmup === true
  );
};

export const onWarmup = async () => {
  try {
    await getAwsSecrets();
    console.log('Warmup completed successfully');
  } catch (error) {
    console.error('Warmup failed:', { error });
  }
};

// Global LRU cache for deduplication
const cache = new LRUCache<string, number>({
  max: 30_000,
  ttl: 30_000,
});

export const _clearDeduplicateCache = (): void => {
  cache.clear();
};

/**
 * FNV-1a hash function for fast string hashing
 */
export const fnv1a = (str: string): string => {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
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
        throw new createError.TooManyRequests(`Duplicate request detected: ${catchCount + 1}`);
      }

      cache.set(key, 1);
    },
  };
};
