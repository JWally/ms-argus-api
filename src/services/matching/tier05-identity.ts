// src/services/matching/tier05-identity.ts
// AR-119: Extracted from matching-service.ts - Identity lookups (Tier 0.5)
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { EvidenceCode, MatchResult } from "./types";

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
 */
export async function tier05PublicKeyLookup(
  deps: Tier05IdentityDeps,
  tenantId: string,
  publicKey: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        tenant_id: { S: tenantId },
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
    };
  }
  return null;
}

/**
 * Tier 0.5: Lookup by evercookie ID
 * Highest confidence - evercookie is hard to clear
 */
export async function tier05CookieLookup(
  deps: Tier05IdentityDeps,
  tenantId: string,
  evercookieId: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        tenant_id: { S: tenantId },
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
    };
  }
  return null;
}

/**
 * Tier 0.5: Lookup by third-party cookie from sigint (AR-81)
 * High confidence - cross-site cookie from CloudFront edge service
 * Survives first-party cookie clearing, provides cross-site identity
 */
export async function tier05SigintIdLookup(
  deps: Tier05IdentityDeps,
  tenantId: string,
  sigintId: string,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.tier1IndexTable,
      Key: {
        tenant_id: { S: tenantId },
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
    };
  }
  return null;
}
