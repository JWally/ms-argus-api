/**
 * @fileoverview cpi → merchantId resolver with per-container in-memory cache.
 *
 * The ingestion hot path needs `merchantId` to stamp on each integrity row so
 * the dashboard's "recent sessions" listing can Query by merchant via the
 * `merchantId-createdAt-index` GSI (instead of fanning out per-cpi).
 *
 * The mapping is immutable for the life of a cpi — a cpi belongs to one
 * merchant-key, which belongs to one merchant, and they are never reassigned.
 * So a Lambda-scope Map cache never invalidates within a container's lifetime.
 * Steady-state cost: zero. Cold-start cost per new cpi: one Query on the
 * platform's merchant-keys `cpi-index` GSI (~5ms, ~0.5 RCU).
 *
 * Negative lookups (unknown cpi) are cached too, with a short TTL — a typo'd
 * or revoked cpi shouldn't trigger a Query on every subsequent request.
 *
 * @module helpers/cpi-merchant-resolver
 */

import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

/** TTL for negative cache entries — keeps unknown-cpi cost bounded under abuse. */
const NEGATIVE_TTL_MS = 60_000;

interface CacheEntry {
  merchantId: string | null;
  /** Only meaningful when merchantId === null. */
  expiresAt: number;
}

export interface CpiMerchantResolverDeps {
  ddb: DynamoDBClient;
  /** Platform's merchant-keys table name (env: MERCHANT_KEYS_TABLE). */
  table: string;
  /** GSI name on merchant-keys mapping cpi → row (default cpi-index). */
  indexName?: string;
}

/**
 * Per-container resolver. Construct once at module scope and reuse — the
 * cache lives for the container's lifetime.
 */
export class CpiMerchantResolver {
  private readonly cache = new Map<string, CacheEntry>();
  constructor(private readonly deps: CpiMerchantResolverDeps) {}

  async resolve(cpi: string): Promise<string | null> {
    const cached = this.cache.get(cpi);
    if (cached) {
      if (cached.merchantId !== null) return cached.merchantId;
      if (Date.now() < cached.expiresAt) return null;
    }
    const merchantId = await this.queryMerchantId(cpi);
    this.cache.set(cpi, {
      merchantId,
      expiresAt: merchantId === null ? Date.now() + NEGATIVE_TTL_MS : 0,
    });
    return merchantId;
  }

  private async queryMerchantId(cpi: string): Promise<string | null> {
    const r = await this.deps.ddb.send(
      new QueryCommand({
        TableName: this.deps.table,
        IndexName: this.deps.indexName ?? "cpi-index",
        KeyConditionExpression: "cpi = :cpi",
        ExpressionAttributeValues: { ":cpi": { S: cpi } },
        Limit: 1,
      }),
    );
    const item = r.Items?.[0];
    if (!item) return null;
    const row = unmarshall(item) as { merchantId?: unknown };
    return typeof row.merchantId === "string" ? row.merchantId : null;
  }

  /** Test hook. */
  _clear(): void {
    this.cache.clear();
  }
}
