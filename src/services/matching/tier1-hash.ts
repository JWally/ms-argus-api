// src/services/matching/tier1-hash.ts
// AR-119: Extracted from matching-service.ts - Hash matching (Tier 1)
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { EvidenceCode, Fingerprint, MatchResult } from "./types";

/**
 * Dependencies for tier 1 hash operations
 */
export interface Tier1HashDeps {
  dynamodb: DynamoDBClient;
  tier1IndexTable: string;
}

/**
 * Tier 1: Match by stable or fuzzy hash
 * High confidence - these hashes are computed from multiple signals
 */
export async function tier1HashMatch(
  deps: Tier1HashDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  // Try stable hash first (higher confidence)
  if (fingerprint.stable_hash) {
    const result = await lookupTier1Index(
      deps,
      `stable#${fingerprint.stable_hash}`,
    );
    if (result) {
      return {
        device_id: result.device_id,
        confidence: 0.95,
        match_tier: 1,
        is_new_device: false,
        risk_score: result.risk_score ?? 0.3,
        flags: result.flags ?? [],
        evidence_codes: ["STABLE_HASH_MATCH"] as EvidenceCode[],
      };
    }
  }

  // Try fuzzy hash (slightly lower confidence)
  if (fingerprint.fuzzy_hash) {
    const result = await lookupTier1Index(
      deps,
      `fuzzy#${fingerprint.fuzzy_hash}`,
    );
    if (result) {
      return {
        device_id: result.device_id,
        confidence: 0.85,
        match_tier: 1,
        is_new_device: false,
        risk_score: result.risk_score ?? 0.3,
        flags: result.flags ?? [],
        evidence_codes: ["FUZZY_HASH_MATCH"] as EvidenceCode[],
      };
    }
  }

  return null;
}

/**
 * Lookup a single entry in the Tier 1 index
 */
async function lookupTier1Index(
  deps: Tier1HashDeps,
  hashKey: string,
): Promise<{
  device_id: string;
  risk_score?: number;
  flags?: string[];
} | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        hash_key: { S: hashKey },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      risk_score: item.risk_score,
      flags: item.flags,
    };
  }
  return null;
}
