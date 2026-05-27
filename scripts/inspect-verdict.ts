/**
 * Run buildMerchantResponse against a stored integrity row to see exactly
 * what verdict + scores the projector computes. Lets us diagnose
 * "why did session X get flagged suspicious" without standing up the
 * dashboard pipeline.
 *
 *   npx tsx scripts/inspect-verdict.ts <session_id> [cpi]
 *
 * Defaults to the test CPI used by qr.arcades.click / www-dev-jw scans.
 */

import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { buildMerchantResponse } from "../src/helpers/merchant-projection";

const TABLE = "ms-argus-api-dev-jw-integrity-results-v2";
const DEFAULT_CPI = "argus_cpi_test_UEeqk7Bk7uetxKKDxNmIdB";

async function main() {
  const sessionId = process.argv[2];
  const cpi = process.argv[3] ?? DEFAULT_CPI;
  if (!sessionId) {
    console.error("usage: inspect-verdict.ts <session_id> [cpi]");
    process.exit(1);
  }

  const ddb = new DynamoDBClient({ region: "us-east-1" });
  const r = await ddb.send(
    new GetItemCommand({
      TableName: TABLE,
      Key: {
        cpi: { S: cpi },
        session_id: { S: sessionId },
      },
    }),
  );
  if (!r.Item) {
    console.error(`no row for cpi=${cpi} session_id=${sessionId}`);
    process.exit(2);
  }
  const integrity = unmarshall(r.Item) as Parameters<
    typeof buildMerchantResponse
  >[0]["integrity"];

  const projection = buildMerchantResponse({
    session_id: sessionId,
    integrity,
  });

  console.log("=== verdict + axes ===");
  console.log(
    JSON.stringify(
      {
        verdict: projection.verdict,
        automation: projection.automation,
        device_tampering: projection.device_tampering,
        network_tampering: projection.network_tampering,
        tags: projection.tags,
      },
      null,
      2,
    ),
  );
  console.log();
  console.log("=== UA / browser ===");
  console.log(
    JSON.stringify(projection.identification.browserDetails, null, 2),
  );
  console.log();
  console.log("=== ip / asn ===");
  console.log(
    JSON.stringify(
      {
        ip: projection.ip,
        asn: projection.ipInfo.asn,
        location: projection.ipLocation,
        ipInfo_flags: {
          datacenter: projection.ipInfo.datacenter?.result,
          mobile: projection.ipInfo.mobile?.result,
          vpn: projection.ipInfo.vpn?.result,
          hosting: projection.ipInfo.hosting?.result,
        },
      },
      null,
      2,
    ),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
