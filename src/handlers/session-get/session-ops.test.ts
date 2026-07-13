import { describe, expect, it, vi } from "vitest";
import { GetItemCommand, type DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import { fetchIntegrityResultsByComposite } from "./session-ops";

describe("fetchIntegrityResultsByComposite", () => {
  it("uses a strongly consistent read for immediate scan redemption", async () => {
    const send = vi.fn().mockResolvedValue({
      Item: {
        cpi: { S: "argus_cpi_test_abc" },
        session_id: { S: "session-1" },
        created_at: { N: "1" },
      },
    });
    const metrics = { addMetric: vi.fn() } as unknown as Metrics;

    await fetchIntegrityResultsByComposite("argus_cpi_test_abc", "session-1", {
      dynamodb: { send } as unknown as DynamoDBClient,
      integrityResultsTable: "integrity-results",
      logger: { warn: vi.fn() } as unknown as Logger,
      metrics,
    });

    const command = send.mock.calls[0]?.[0] as GetItemCommand;
    expect(command).toBeInstanceOf(GetItemCommand);
    expect(command.input).toMatchObject({
      TableName: "integrity-results",
      ConsistentRead: true,
      Key: {
        cpi: { S: "argus_cpi_test_abc" },
        session_id: { S: "session-1" },
      },
    });
  });
});
