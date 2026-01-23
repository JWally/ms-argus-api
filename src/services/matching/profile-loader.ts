// src/services/matching/profile-loader.ts
// AR-157: Extracted shared profile loading logic from tier2-compound and session-anchors
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

/**
 * Minimal dependencies for loading a profile
 * Both Tier2CompoundDeps and SessionAnchorDeps satisfy this interface
 */
export interface ProfileLoaderDeps {
  dynamodb: DynamoDBClient;
  profilesTable: string;
}

/**
 * Profile data returned from DynamoDB lookup
 */
export interface ProfileData {
  risk_score: number;
  flags: string[];
  fuzzy_hash?: string;
}

/**
 * Load device profile from DynamoDB
 * Returns risk_score and flags for the device, or null if not found
 */
export async function loadProfile(
  deps: ProfileLoaderDeps,
  deviceId: string,
): Promise<ProfileData | null> {
  const result = await deps.dynamodb.send(
    new GetItemCommand({
      TableName: deps.profilesTable,
      Key: {
        device_id: { S: deviceId },
      },
      ProjectionExpression: "risk_score, flags, fuzzy_hash",
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      risk_score: item.risk_score,
      flags: item.flags ?? [],
      fuzzy_hash: item.fuzzy_hash,
    };
  }
  return null;
}
