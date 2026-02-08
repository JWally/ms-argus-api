import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { computeFuzzyMatchInfo } from "../../helpers/hash";
import { MatchTier } from "../../types/matching-tiers";
import { EvidenceCode, MatchResult } from "./types";

export interface IndexLookupDeps {
  dynamodb: DynamoDBClient;
  tier1IndexTable: string;
}

interface IdentityLookupConfig {
  prefix: string;
  confidence: number;
  evidenceCode: EvidenceCode;
}

const PUBKEY_CONFIG: IdentityLookupConfig = {
  prefix: "pubkey#",
  confidence: 0.99,
  evidenceCode: "PUBLIC_KEY_MATCH",
};

const COOKIE_CONFIG: IdentityLookupConfig = {
  prefix: "evercookie#",
  confidence: 0.99,
  evidenceCode: "EVERCOOKIE_MATCH",
};

const SIGINT_CONFIG: IdentityLookupConfig = {
  prefix: "sigint#",
  confidence: 0.98,
  evidenceCode: "SIGINT_ID_MATCH",
};

// Shared DynamoDB GetItem against the tier-1 index table.
async function lookupIndex(
  deps: IndexLookupDeps,
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

// --- Identity lookups (tier 0.5) ---

async function identityLookup(
  deps: IndexLookupDeps,
  id: string,
  config: IdentityLookupConfig,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  const result = await lookupIndex(deps, `${config.prefix}${id}`);

  if (result) {
    return {
      device_id: result.device_id,
      confidence: config.confidence,
      match_tier: MatchTier.IDENTITY,
      is_new_device: false,
      risk_score: result.risk_score ?? 0.3,
      flags: result.flags ?? [],
      evidence_codes: [config.evidenceCode],
      fuzzy_match_info: computeFuzzyMatchInfo(
        incomingFuzzyHash,
        result.fuzzy_hash,
      ),
    };
  }
  return null;
}

export function publicKeyLookup(
  deps: IndexLookupDeps,
  publicKey: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, publicKey, PUBKEY_CONFIG, incomingFuzzyHash);
}

export function cookieLookup(
  deps: IndexLookupDeps,
  evercookieId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, evercookieId, COOKIE_CONFIG, incomingFuzzyHash);
}

export function sigintIdLookup(
  deps: IndexLookupDeps,
  sigintId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, sigintId, SIGINT_CONFIG, incomingFuzzyHash);
}
