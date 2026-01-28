/**
 * Dump a sample payload to see its structure
 *
 * Run: npx ts-node scripts/dump-payload.ts
 */
import { DynamoDBClient, ScanCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const dynamodb = new DynamoDBClient({ region: "us-east-1" });
const tableName = "ms-argus-api-dev-jw-session-payload";

async function main() {
  const result = await dynamodb.send(
    new ScanCommand({
      TableName: tableName,
      Limit: 1,
    }),
  );

  if (result.Items && result.Items.length > 0) {
    const item = unmarshall(result.Items[0]);
    console.log(JSON.stringify(item, null, 2));
  } else {
    console.log("No items found");
  }
}

main().catch(console.error);
