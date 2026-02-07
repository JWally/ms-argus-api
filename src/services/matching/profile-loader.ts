import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

/**
 * Minimal dependencies for loading a profile.
 *
 * Both Tier2CompoundDeps and SessionAnchorDeps satisfy this interface.
 */
export interface ProfileLoaderDeps {
  /** DynamoDB client for profile queries */
  dynamodb: DynamoDBClient;
  /** Profiles table name */
  profilesTable: string;
}

/** Core profile data returned from loader. */
export interface ProfileData {
  /** Device risk score (0.0 to 1.0) */
  risk_score: number;
  /** Array of risk flags for the device */
  flags: string[];
  /** SimHash fuzzy hash for drift detection */
  fuzzy_hash?: string;
  /** IP history ring buffer */
  ip_history?: import("../../types/profile").IpHistoryEntry[];
}

/**
 * Load device profile from DynamoDB.
 *
 * Retrieves risk_score, flags, and fuzzy_hash for a device. Returns null
 * if the device has no existing profile.
 *
 * @param deps - DynamoDB client and table name
 * @param deviceId - Device ID to load profile for
 * @returns Profile data if found, null otherwise
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
      ProjectionExpression: "risk_score, flags, fuzzy_hash, ip_history",
    }),
  );

  if (result.Item) {
    const item = unmarshall(result.Item);
    return {
      risk_score: item.risk_score,
      flags: item.flags ?? [],
      fuzzy_hash: item.fuzzy_hash,
      ip_history: item.ip_history,
    };
  }
  return null;
}
