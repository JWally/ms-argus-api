// src/services/matching/tier1-hash.ts
// AR-119: Extracted from matching-service.ts - Hash matching (Tier 1)
// AR-XXX: Added fuzzy_match_info for drift detection
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { hammingDistance } from "../../helpers/bucket-keys";
import {
  EvidenceCode,
  Fingerprint,
  FuzzyMatchInfo,
  MatchResult,
} from "./types";

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
 * AR-XXX: Now includes fuzzy_match_info for drift detection
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
        // AR-XXX: Compute drift from stored fuzzy_hash
        fuzzy_match_info: computeFuzzyMatchInfo(
          fingerprint.fuzzy_hash,
          result.fuzzy_hash,
        ),
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
        // AR-XXX: Compute drift from stored fuzzy_hash
        fuzzy_match_info: computeFuzzyMatchInfo(
          fingerprint.fuzzy_hash,
          result.fuzzy_hash,
        ),
      };
    }
  }

  return null;
}

/**
 * Lookup a single entry in the Tier 1 index
 * AR-XXX: Added fuzzy_hash for drift detection
 */
async function lookupTier1Index(
  deps: Tier1HashDeps,
  hashKey: string,
): Promise<{
  device_id: string;
  risk_score?: number;
  flags?: string[];
  fuzzy_hash?: string;
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
      fuzzy_hash: item.fuzzy_hash,
    };
  }
  return null;
}

/**
 * AR-XXX: Compute fuzzy match info for drift detection
 * Computes Hamming distance between incoming and stored fuzzy_hash
 */
function computeFuzzyMatchInfo(
  incomingHash: string | undefined,
  storedHash: string | undefined,
): FuzzyMatchInfo | undefined {
  if (!incomingHash || !storedHash) {
    return undefined;
  }

  const distance = hammingDistance(incomingHash, storedHash);

  return {
    incoming_hash: incomingHash,
    stored_hash: storedHash,
    hamming_distance: distance,
    similarity: distance >= 0 ? 1 - distance / 64 : 0,
  };
}
