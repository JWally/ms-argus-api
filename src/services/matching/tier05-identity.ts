/**
 * Tier 0.5 identity matching via persistent identifiers.
 *
 * Provides high-confidence matching using stable identity signals like
 * public keys, evercookies, and SIGINT IDs. These bypass fingerprint
 * comparison when a known identifier is present.
 * @module
 */
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { computeFuzzyMatchInfo } from "../../helpers/hash";
import { EvidenceCode, MatchResult } from "./types";

/** Dependencies for tier 0.5 identity lookups. */
export interface Tier05IdentityDeps {
  /** DynamoDB client for index queries */
  dynamodb: DynamoDBClient;
  /** Tier-1 index table name */
  tier1IndexTable: string;
}

/** Configuration for a specific identity lookup type. */
interface IdentityLookupConfig {
  /** Key prefix in tier-1 index (e.g., "pubkey#") */
  prefix: string;
  /** Confidence score for matches (0.0 to 1.0) */
  confidence: number;
  /** Evidence code to include in match result */
  evidenceCode: EvidenceCode;
}

/** Public key lookup: highest confidence identity signal. */
const PUBKEY_CONFIG: IdentityLookupConfig = {
  prefix: "pubkey#",
  confidence: 0.99,
  evidenceCode: "PUBLIC_KEY_MATCH",
};

/** Evercookie lookup: persistent browser storage identifier. */
const COOKIE_CONFIG: IdentityLookupConfig = {
  prefix: "evercookie#",
  confidence: 0.99,
  evidenceCode: "EVERCOOKIE_MATCH",
};

/** SIGINT ID lookup: signal intelligence identifier. */
const SIGINT_CONFIG: IdentityLookupConfig = {
  prefix: "sigint#",
  confidence: 0.98,
  evidenceCode: "SIGINT_ID_MATCH",
};

/**
 * Perform identity lookup against tier-1 index.
 *
 * Generic lookup function used by all identity types. Queries the index
 * using the configured prefix and returns a match result if found.
 *
 * @param deps - DynamoDB client and table name
 * @param id - Identity value to look up
 * @param config - Lookup configuration (prefix, confidence, evidence code)
 * @param incomingFuzzyHash - Optional fuzzy hash for drift detection
 * @returns Match result if found, null otherwise
 */
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

/**
 * Look up device by cryptographic public key.
 *
 * @param deps - DynamoDB client and table name
 * @param publicKey - Public key to match
 * @param incomingFuzzyHash - Optional fuzzy hash for drift detection
 * @returns Match result if found, null otherwise
 */
export function tier05PublicKeyLookup(
  deps: Tier05IdentityDeps,
  publicKey: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, publicKey, PUBKEY_CONFIG, incomingFuzzyHash);
}

/**
 * Look up device by evercookie identifier.
 *
 * @param deps - DynamoDB client and table name
 * @param evercookieId - Evercookie ID to match
 * @param incomingFuzzyHash - Optional fuzzy hash for drift detection
 * @returns Match result if found, null otherwise
 */
export function tier05CookieLookup(
  deps: Tier05IdentityDeps,
  evercookieId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, evercookieId, COOKIE_CONFIG, incomingFuzzyHash);
}

/**
 * Look up device by SIGINT identifier.
 *
 * @param deps - DynamoDB client and table name
 * @param sigintId - SIGINT ID to match
 * @param incomingFuzzyHash - Optional fuzzy hash for drift detection
 * @returns Match result if found, null otherwise
 */
export function tier05SigintIdLookup(
  deps: Tier05IdentityDeps,
  sigintId: string,
  incomingFuzzyHash?: string,
): Promise<MatchResult | null> {
  return identityLookup(deps, sigintId, SIGINT_CONFIG, incomingFuzzyHash);
}
