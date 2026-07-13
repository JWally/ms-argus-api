/**
 * @fileoverview Session retrieval operations for the session-get handler.
 *
 * Single read path: composite-key fetch by `(cpi, session_id)`. Used by the
 * merchant REST API route after the inbound token has been verified to
 * bind the same `cpi`.
 *
 * @module handlers/session-get/session-ops
 */

import { APIGatewayProxyEvent } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

/**
 * Extracts and validates `session_id` from the path. Caller is expected to
 * have already verified the HTTP method — this handler is mounted on a
 * GET-only route.
 */
export function extractSessionId(
  event: APIGatewayProxyEvent,
  metrics: Metrics,
): string {
  const sessionId = event.pathParameters?.session_id;
  if (!sessionId) {
    metrics.addMetric("MissingSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Missing session_id parameter");
  }
  if (sessionId.length > 1024 || !/^[\w-]+$/.test(sessionId)) {
    metrics.addMetric("InvalidSessionId", MetricUnit.Count, 1);
    throw new HttpError(400, "Invalid session_id format");
  }
  return sessionId;
}

export async function fetchIntegrityResultsByComposite(
  cpi: string,
  sessionId: string,
  deps: {
    dynamodb: DynamoDBClient;
    integrityResultsTable: string;
    logger: Logger;
    metrics: Metrics;
  },
): Promise<IntegrityResultsData | undefined> {
  try {
    const result = await deps.dynamodb.send(
      new GetItemCommand({
        TableName: deps.integrityResultsTable,
        // Pair redeems a scan immediately after ingestion returns. An eventual
        // read can briefly miss that committed row and turn a valid scan into
        // a fail-closed projection_lookup_failed verdict.
        ConsistentRead: true,
        Key: {
          cpi: { S: cpi },
          session_id: { S: sessionId },
        },
      }),
    );

    if (!result.Item) {
      deps.metrics.addMetric("IntegrityResultsNotFound", MetricUnit.Count, 1);
      return undefined;
    }

    const item = unmarshall(result.Item) as IntegrityResultsData;
    deps.metrics.addMetric("IntegrityResultsFound", MetricUnit.Count, 1);
    return item;
  } catch (error) {
    deps.logger.warn("Failed to fetch integrity results", {
      error,
      cpi,
      session_id: sessionId,
    });
    deps.metrics.addMetric("IntegrityResultsFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}
