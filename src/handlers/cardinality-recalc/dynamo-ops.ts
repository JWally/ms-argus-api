import { Logger } from "@aws-lambda-powertools/logger";
import {
  DynamoDBClient,
  ScanCommand,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { TIER2_STATS_SK } from "../../helpers/constants";

export async function* scanBucketKeysPages(
  tableName: string,
  deps: { dynamodb: DynamoDBClient; logger: Logger },
): AsyncGenerator<Set<string>, void, undefined> {
  let lastEvaluatedKey: Record<string, unknown> | undefined;
  let pageNumber = 0;

  do {
    pageNumber++;
    const response = await deps.dynamodb.send(
      new ScanCommand({
        TableName: tableName,
        ProjectionExpression: "bucket_key",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    const pageKeys = new Set<string>();
    for (const item of response.Items || []) {
      if (item.bucket_key?.S) {
        pageKeys.add(item.bucket_key.S);
      }
    }

    deps.logger.debug("Scanned bucket keys page", {
      pageNumber,
      keysInPage: pageKeys.size,
      hasMorePages: !!response.LastEvaluatedKey,
    });

    yield pageKeys;

    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);
}

export async function countBucketDevices(
  tableName: string,
  bucketKey: string,
  dynamodb: DynamoDBClient,
): Promise<number> {
  let count = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const response = await dynamodb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: "bucket_key = :pk",
        FilterExpression: "device_id <> :stats_sk",
        ExpressionAttributeValues: {
          ":pk": { S: bucketKey },
          ":stats_sk": { S: TIER2_STATS_SK },
        },
        Select: "COUNT",
        ExclusiveStartKey: lastEvaluatedKey as
          | Record<string, { S: string }>
          | undefined,
      }),
    );

    count += response.Count || 0;
    lastEvaluatedKey = response.LastEvaluatedKey as
      | Record<string, unknown>
      | undefined;
  } while (lastEvaluatedKey);

  return count;
}

export async function getCurrentCardinality(
  tableName: string,
  bucketKey: string,
  dynamodb: DynamoDBClient,
): Promise<number> {
  const response = await dynamodb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: "bucket_key = :pk AND device_id = :sk",
      ExpressionAttributeValues: {
        ":pk": { S: bucketKey },
        ":sk": { S: TIER2_STATS_SK },
      },
      ProjectionExpression: "cardinality",
    }),
  );

  const item = response.Items?.[0];
  if (item?.cardinality?.N) {
    return parseInt(item.cardinality.N, 10);
  }
  return 0;
}

export async function updateCardinality(
  params: {
    tableName: string;
    bucketKey: string;
    cardinality: number;
    ttl: number;
  },
  dynamodb: DynamoDBClient,
): Promise<void> {
  const { tableName, bucketKey, cardinality, ttl } = params;
  await dynamodb.send(
    new UpdateItemCommand({
      TableName: tableName,
      Key: {
        bucket_key: { S: bucketKey },
        device_id: { S: TIER2_STATS_SK },
      },
      UpdateExpression: "SET cardinality = :c, #ttl = :ttl",
      ExpressionAttributeNames: {
        "#ttl": "ttl",
      },
      ExpressionAttributeValues: {
        ":c": { N: String(cardinality) },
        ":ttl": { N: String(ttl) },
      },
    }),
  );
}
