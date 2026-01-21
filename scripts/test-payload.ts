import {
  DynamoDBClient,
  PutItemCommand,
  GetItemCommand,
} from "@aws-sdk/client-dynamodb";
import { marshall, unmarshall } from "@aws-sdk/util-dynamodb";

const dynamodb = new DynamoDBClient({ region: "us-east-1" });
const tableName = "ms-argus-api-dev-jw-session-payload";
const testSessionId = "test-session-" + Date.now();

async function main() {
  // Write test item
  const ttl = Math.floor(Date.now() / 1000) + 1800;
  const item = {
    session_id: testSessionId,
    payload: { test: "payload", nested: { key: "value" } },
    ttl,
    created_at: new Date().toISOString(),
  };

  console.log("Writing test item to", tableName);
  console.log("Session ID:", testSessionId);

  await dynamodb.send(
    new PutItemCommand({
      TableName: tableName,
      Item: marshall(item, { removeUndefinedValues: true }),
    }),
  );
  console.log("Write successful!");

  // Read back
  const result = await dynamodb.send(
    new GetItemCommand({
      TableName: tableName,
      Key: { session_id: { S: testSessionId } },
    }),
  );

  if (result.Item) {
    console.log("Read successful!");
    console.log("Item:", JSON.stringify(unmarshall(result.Item), null, 2));
  } else {
    console.log("Item not found!");
  }
}

main();
