// src/services/matching/session-anchors.ts
// AR-119: Extracted from matching-service.ts - Session anchor lookups
import {
  DynamoDBClient,
  QueryCommand,
  GetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
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

/**
 * Dependencies for session anchor operations
 */
export interface SessionAnchorDeps {
  dynamodb: DynamoDBClient;
  tier2BucketsTable: string;
  profilesTable: string;
}

/**
 * AR-82: Build session anchor bucket key for ephemeral matching
 * AR-117: Delegates to shared bucket-keys helper
 */
export function buildSessionAnchorKey(fingerprint: Fingerprint): string | null {
  return buildSessionAnchorKeyHelper(fingerprint);
}

/**
 * AR-82: Lookup by session anchor bucket with 10-minute validity window
 * Used for short-session matching when other signals fail
 * Application-side enforced validity (DynamoDB TTL is for cleanup only)
 */
export async function sessionAnchorLookup(
  deps: SessionAnchorDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const bucketKey = buildSessionAnchorKey(fingerprint);
  if (!bucketKey) {
    return null;
  }

  // Query the session anchor bucket for matching devices
  // AR-121: ScanIndexForward:false returns newest entries first (by device_id sort key)
  // With ULID device IDs, this returns most recently created devices first
  const result = await deps.dynamodb.send(
    new QueryCommand({
      TableName: deps.tier2BucketsTable,
      KeyConditionExpression: "bucket_key = :bk",
      ExpressionAttributeValues: {
        ":bk": { S: bucketKey },
      },
      ProjectionExpression: "device_id, created_at",
      Limit: 10, // Only need recent entries
      ScanIndexForward: false, // AR-121: Descending order by sort key (device_id)
    }),
  );

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const now = Date.now();
  const validityWindowMs = SESSION_ANCHOR_VALIDITY_SECONDS * 1000;

  // AR-95: Sort by created_at descending to find the most recent entry first
  // DynamoDB Query returns items sorted by sort key (device_id), not by created_at
  const sortedItems = result.Items.map((item) => unmarshall(item))
    .filter((item) => item.device_id !== TIER2_STATS_SK) // Filter out stats entries
    .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0)); // Most recent first

  // Find the most recent valid entry
  for (const item of sortedItems) {
    const deviceId = item.device_id;
    const createdAt = item.created_at;

    // Check if within 10-minute validity window
    if (createdAt && now - createdAt <= validityWindowMs) {
      const profile = await loadProfile(deps, deviceId);
      return {
        device_id: deviceId,
        confidence: 0.65, // Lower confidence than multi-bucket tier2 matches
        match_tier: 2,
        is_new_device: false,
        risk_score: profile?.risk_score ?? 0.4,
        flags: profile?.flags ?? [],
        evidence_codes: ["SESSION_ANCHOR_BUCKET"] as EvidenceCode[],
      };
    }
  }

  return null;
}

/**
 * AR-94: Build IP+UA-only anchor bucket key for ephemeral matching
 * AR-117: Delegates to shared bucket-keys helper
 */
export function buildIpUaAnchorKey(fingerprint: Fingerprint): string | null {
  return buildIpUaAnchorKeyHelper(fingerprint);
}

/**
 * AR-94: Lookup by IP+UA-only anchor bucket with 3-minute validity window
 * Shorter window than session anchor since it's less specific (no screen_dims)
 * Catches cases where screen changes (dock/undock) but IP+UA stays same
 */
export async function ipUaAnchorLookup(
  deps: SessionAnchorDeps,
  fingerprint: Fingerprint,
): Promise<MatchResult | null> {
  const bucketKey = buildIpUaAnchorKey(fingerprint);
  if (!bucketKey) {
    return null;
  }

  // Query the IP+UA anchor bucket for matching devices
  // AR-121: ScanIndexForward:false returns newest entries first (by device_id sort key)
  // With ULID device IDs, this returns most recently created devices first
  const result = await deps.dynamodb.send(
    new QueryCommand({
      TableName: deps.tier2BucketsTable,
      KeyConditionExpression: "bucket_key = :bk",
      ExpressionAttributeValues: {
        ":bk": { S: bucketKey },
      },
      ProjectionExpression: "device_id, created_at",
      Limit: 10, // Only need recent entries
      ScanIndexForward: false, // AR-121: Descending order by sort key (device_id)
    }),
  );

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const now = Date.now();
  const validityWindowMs = IP_UA_ANCHOR_VALIDITY_SECONDS * 1000;

  // AR-95: Sort by created_at descending to find the most recent entry first
  // DynamoDB Query returns items sorted by sort key (device_id), not by created_at
  const sortedItems = result.Items.map((item) => unmarshall(item))
    .filter((item) => item.device_id !== TIER2_STATS_SK) // Filter out stats entries
    .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0)); // Most recent first

  // Find the most recent valid entry
  for (const item of sortedItems) {
    const deviceId = item.device_id;
    const createdAt = item.created_at;

    // Check if within 3-minute validity window
    if (createdAt && now - createdAt <= validityWindowMs) {
      const profile = await loadProfile(deps, deviceId);
      return {
        device_id: deviceId,
        confidence: 0.6, // Lower than session anchor (less specific)
        match_tier: 2,
        is_new_device: false,
        risk_score: profile?.risk_score ?? 0.4,
        flags: profile?.flags ?? [],
        evidence_codes: ["IP_UA_ANCHOR_BUCKET"] as EvidenceCode[],
      };
    }
  }

  return null;
}

/**
 * Load device profile from DynamoDB
 */
async function loadProfile(
  deps: SessionAnchorDeps,
  deviceId: string,
): Promise<{ risk_score: number; flags: string[] } | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.profilesTable,
      Key: {
        device_id: { S: deviceId },
      },
      ProjectionExpression: "risk_score, flags",
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      risk_score: item.risk_score,
      flags: item.flags ?? [],
    };
  }
  return null;
}
