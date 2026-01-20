// src/services/matching/tier05-identity.ts
// AR-119: Extracted from matching-service.ts - Identity lookups (Tier 0.5)
// AR-XXX: Added fuzzy_match_info for drift detection
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { hammingDistance } from "../../helpers/bucket-keys";
import { EvidenceCode, FuzzyMatchInfo, MatchResult } from "./types";

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

/**
 * Dependencies for tier 0.5 identity operations
 */
export interface Tier05IdentityDeps {
  dynamodb: DynamoDBClient;
  tier1IndexTable: string;
}

/**
 * Tier 0.5: Lookup by ECDSA public key (AR-64)
 * Near-perfect confidence - cryptographic identity stored in IndexedDB
 * Private key is non-extractable, so public key proves device possession
 * AR-XXX: Now includes fuzzy_match_info for drift detection
 */
export async function tier05PublicKeyLookup(
  deps: Tier05IdentityDeps,
  publicKey: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        hash_key: { S: `pubkey#${publicKey}` },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      confidence: 0.99,
      match_tier: 0.5,
      is_new_device: false,
      risk_score: item.risk_score ?? 0.3,
      flags: item.flags ?? [],
      evidence_codes: ["PUBLIC_KEY_MATCH"] as EvidenceCode[],
      // AR-XXX: Compute drift from stored fuzzy_hash
      fuzzy_match_info: computeFuzzyMatchInfo(
        incomingFuzzyHash,
        item.fuzzy_hash,
      ),
    };
  }
  return null;
}

/**
 * Tier 0.5: Lookup by evercookie ID
 * Highest confidence - evercookie is hard to clear
 * AR-XXX: Now includes fuzzy_match_info for drift detection
 */
export async function tier05CookieLookup(
  deps: Tier05IdentityDeps,
  evercookieId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        hash_key: { S: `evercookie#${evercookieId}` },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      confidence: 0.99,
      match_tier: 0.5,
      is_new_device: false,
      risk_score: item.risk_score ?? 0.3,
      flags: item.flags ?? [],
      evidence_codes: ["EVERCOOKIE_MATCH"] as EvidenceCode[],
      // AR-XXX: Compute drift from stored fuzzy_hash
      fuzzy_match_info: computeFuzzyMatchInfo(
        incomingFuzzyHash,
        item.fuzzy_hash,
      ),
    };
  }
  return null;
}

/**
 * Tier 0.5: Lookup by third-party cookie from sigint (AR-81)
 * High confidence - cross-site cookie from CloudFront edge service
 * Survives first-party cookie clearing, provides cross-site identity
 * AR-XXX: Now includes fuzzy_match_info for drift detection
 */
export async function tier05SigintIdLookup(
  deps: Tier05IdentityDeps,
  sigintId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        hash_key: { S: `sigint#${sigintId}` },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      confidence: 0.98, // Slightly lower than evercookie (can be shared across browsers)
      match_tier: 0.5,
      is_new_device: false,
      risk_score: item.risk_score ?? 0.3,
      flags: item.flags ?? [],
      evidence_codes: ["SIGINT_ID_MATCH"] as EvidenceCode[],
      // AR-XXX: Compute drift from stored fuzzy_hash
      fuzzy_match_info: computeFuzzyMatchInfo(
        incomingFuzzyHash,
        item.fuzzy_hash,
      ),
    };
  }
  return null;
}
