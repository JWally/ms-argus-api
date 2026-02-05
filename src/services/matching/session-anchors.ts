import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { loadProfile } from "./profile-loader";
import {
  SESSION_ANCHOR_VALIDITY_SECONDS,
  IP_UA_ANCHOR_VALIDITY_SECONDS,
  TIER2_STATS_SK,
} from "../../helpers/constants";
import {
  buildSessionAnchorKey,
  buildIpUaAnchorKey,
} from "../../helpers/bucket-keys";
import { EvidenceCode, Fingerprint, MatchResult } from "./types";

/**
 * Dependencies for session anchor lookup operations
 */
export interface SessionAnchorDeps {
  /** DynamoDB client instance */
  dynamodb: DynamoDBClient;
  /** Name of the tier 2 buckets table */
  tier2BucketsTable: string;
  /** Name of the profiles table */
  profilesTable: string;
}

/**
 * Configuration for anchor lookup behavior
 */
interface AnchorConfig {
  /** How long anchor entries are valid in seconds */
  validitySeconds: number;
  /** Confidence score to assign to anchor matches */
  confidence: number;
  /** Evidence code to include in match result */
  evidenceCode: EvidenceCode;
}

/**
 * Look up a device by anchor bucket key with time validity check
 * @param deps - Dependencies including DynamoDB client and table names
 * @param bucketKey - The anchor bucket key to query
 * @param config - Anchor configuration (validity, confidence, evidence)
 * @returns Match result if valid anchor found, null otherwise
 */
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

/**
 * Look up device by session anchor (short-lived, high specificity)
 * Session anchors are valid for ~10 minutes and use multiple signals
 * @param deps - Dependencies including DynamoDB client and table names
 * @param fingerprint - The fingerprint containing anchor signals
 * @returns Match result if valid session anchor found, null otherwise
 */
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

/**
 * Look up device by IP+UserAgent anchor (very short-lived fallback)
 * IP+UA anchors are valid for ~3 minutes and are less specific than session anchors
 * @param deps - Dependencies including DynamoDB client and table names
 * @param fingerprint - The fingerprint containing IP and user agent
 * @returns Match result if valid IP+UA anchor found, null otherwise
 */
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
