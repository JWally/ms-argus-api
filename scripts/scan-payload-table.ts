import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const dynamodb = new DynamoDBClient({ region: "us-east-1" });
const tableName = "ms-argus-api-dev-jw-session-payload";

async function main() {
  const result = await dynamodb.send(
    new ScanCommand({
      TableName: tableName,
      Limit: 10,
    }),
  );

  console.log("Items in table:", result.Count);
  console.log("Scanned count:", result.ScannedCount);

  if (result.Items) {
    for (const item of result.Items) {
      const unmarshalled = unmarshall(item);
      console.log("\n--- Session:", unmarshalled.session_id);
      console.log("Created:", unmarshalled.created_at);
      console.log("Has payload:", !!unmarshalled.payload);
    }
  }
}

main();
