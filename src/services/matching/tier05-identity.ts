import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { computeFuzzyMatchInfo } from "../../helpers/hash";
import { EvidenceCode, MatchResult } from "./types";

export interface Tier05IdentityDeps {
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

async function identityLookup(
  deps: Tier05IdentityDeps,
  id: string,
  config: IdentityLookupConfig,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        hash_key: { S: `${config.prefix}${id}` },
      },
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      device_id: item.device_id,
      confidence: config.confidence,
      match_tier: 0.5,
      is_new_device: false,
      risk_score: item.risk_score ?? 0.3,
      flags: item.flags ?? [],
      evidence_codes: [config.evidenceCode],
      fuzzy_match_info: computeFuzzyMatchInfo(
        incomingFuzzyHash,
        item.fuzzy_hash,
      ),
    };
  }
  return null;
}

export function tier05PublicKeyLookup(
  deps: Tier05IdentityDeps,
  publicKey: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, publicKey, PUBKEY_CONFIG, incomingFuzzyHash);
}

export function tier05CookieLookup(
  deps: Tier05IdentityDeps,
  evercookieId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, evercookieId, COOKIE_CONFIG, incomingFuzzyHash);
}

export function tier05SigintIdLookup(
  deps: Tier05IdentityDeps,
  sigintId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, sigintId, SIGINT_CONFIG, incomingFuzzyHash);
}
