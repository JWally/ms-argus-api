import { beforeEach, describe, expect, it, vi } from "vitest";
import type { APIGatewayProxyEvent } from "aws-lambda";
import { GetItemCommand, type DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { Logger } from "@aws-lambda-powertools/logger";
import type { Metrics } from "@aws-lambda-powertools/metrics";
import { HttpError } from "../../helpers/http-error";
import {
  extractSessionId,
  fetchIntegrityResultsByComposite,
} from "./session-ops";

const send = vi.fn();
const logger = { warn: vi.fn() } as unknown as Logger;
const metrics = { addMetric: vi.fn() } as unknown as Metrics;
const dependencies = {
  dynamodb: { send } as unknown as DynamoDBClient,
  integrityResultsTable: "integrity-results",
  logger,
  metrics,
};

function event(sessionId?: string): APIGatewayProxyEvent {
  return {
    pathParameters: sessionId === undefined ? {} : { session_id: sessionId },
  } as unknown as APIGatewayProxyEvent;
}

describe("session-get persistence adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("extracts a valid session ID", () => {
    expect(extractSessionId(event("session_1-a"), metrics)).toBe("session_1-a");
  });

  it("rejects a missing session ID with telemetry", () => {
    expect(() => extractSessionId(event(), metrics)).toThrowError(
      new HttpError(400, "Missing session_id parameter"),
    );
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "MissingSessionId",
      "Count",
      1,
    );
  });

  it.each(["session/1", "x".repeat(1025)])(
    "rejects malformed session ID %s",
    (sessionId) => {
      expect(() => extractSessionId(event(sessionId), metrics)).toThrowError(
        new HttpError(400, "Invalid session_id format"),
      );
      expect(metrics.addMetric).toHaveBeenCalledWith(
        "InvalidSessionId",
        "Count",
        1,
      );
    },
  );

  it("uses a strongly consistent read and returns the unmarshalled row", async () => {
    send.mockResolvedValueOnce({
      Item: {
        cpi: { S: "argus_cpi_test_abc" },
        session_id: { S: "session-1" },
        created_at: { N: "1" },
      },
    });

    await expect(
      fetchIntegrityResultsByComposite(
        "argus_cpi_test_abc",
        "session-1",
        dependencies,
      ),
    ).resolves.toMatchObject({
      cpi: "argus_cpi_test_abc",
      session_id: "session-1",
      created_at: 1,
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
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "IntegrityResultsFound",
      "Count",
      1,
    );
  });

  it("returns undefined and records a missing row", async () => {
    send.mockResolvedValueOnce({});
    await expect(
      fetchIntegrityResultsByComposite(
        "argus_cpi_test_abc",
        "session-1",
        dependencies,
      ),
    ).resolves.toBeUndefined();
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "IntegrityResultsNotFound",
      "Count",
      1,
    );
  });

  it("fails closed and records an AWS read failure", async () => {
    const error = new Error("ddb unavailable");
    send.mockRejectedValueOnce(error);
    await expect(
      fetchIntegrityResultsByComposite(
        "argus_cpi_test_abc",
        "session-1",
        dependencies,
      ),
    ).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(
      "Failed to fetch integrity results",
      {
        error,
        cpi: "argus_cpi_test_abc",
        session_id: "session-1",
      },
    );
    expect(metrics.addMetric).toHaveBeenCalledWith(
      "IntegrityResultsFetchError",
      "Count",
      1,
    );
  });
});
