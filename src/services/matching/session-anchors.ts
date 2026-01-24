import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { loadProfile } from "./profile-loader";
import {
  SESSION_ANCHOR_VALIDITY_SECONDS,
  IP_UA_ANCHOR_VALIDITY_SECONDS,
  TIER2_STATS_SK,
} from "../../helpers/constants";
import {
  buildSessionAnchorKey as buildSessionAnchorKeyHelper,
  buildIpUaAnchorKey as buildIpUaAnchorKeyHelper,
} from "../../helpers/bucket-keys";
import { EvidenceCode, Fingerprint, MatchResult } from "./types";

export interface SessionAnchorDeps {
  dynamodb: DynamoDBClient;
  tier2BucketsTable: string;
  profilesTable: string;
}

export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  return buildSessionAnchorKeyHelper(fingerprint);
}

export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  return buildIpUaAnchorKeyHelper(fingerprint);
}

interface AnchorConfig {
  validitySeconds: number;
  confidence: number;
  evidenceCode: EvidenceCode;
}

async function anchorLookup(
  deps: SessionAnchorDeps,
  bucketKey: string,
  config: AnchorConfig,
): Promise<MatchResult | null> {
  const result = await deps.dynamodb.send(
    new QueryCommand({
      TableName: deps.tier2BucketsTable,
      KeyConditionExpression: "bucket_key = :bk",
      ExpressionAttributeValues: { ":bk": { S: bucketKey } },
      ProjectionExpression: "device_id, created_at",
      Limit: 10,
      ScanIndexForward: false,
    }),
  );

  if (!result.Items?.length) return null;

  const now = Date.now();
  const validityWindowMs = config.validitySeconds * 1000;
  const sortedItems = result.Items.map((item) => unmarshall(item))
    .filter((item) => item.device_id !== TIER2_STATS_SK)
    .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));

  for (const item of sortedItems) {
    if (item.created_at && now - item.created_at <= validityWindowMs) {
      const profile = await loadProfile(deps, item.device_id);
      return {
        device_id: item.device_id,
        confidence: config.confidence,
        match_tier: 2,
        is_new_device: false,
        risk_score: profile?.risk_score ?? 0.4,
        flags: profile?.flags ?? [],
        evidence_codes: [config.evidenceCode],
      };
    }
  }
  return null;
}

export async function sessionAnchorLookup(
  deps: SessionAnchorDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const bucketKey = buildSessionAnchorKey(fingerprint);
  if (!bucketKey) return null;
  return anchorLookup(deps, bucketKey, {
    validitySeconds: SESSION_ANCHOR_VALIDITY_SECONDS,
    confidence: 0.65,
    evidenceCode: "SESSION_ANCHOR_BUCKET",
  });
}

export async function ipUaAnchorLookup(
  deps: SessionAnchorDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const bucketKey = buildIpUaAnchorKey(fingerprint);
  if (!bucketKey) return null;
  return anchorLookup(deps, bucketKey, {
    validitySeconds: IP_UA_ANCHOR_VALIDITY_SECONDS,
    confidence: 0.6,
    evidenceCode: "IP_UA_ANCHOR_BUCKET",
  });
}
