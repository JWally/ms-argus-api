/**
 * @fileoverview Session retrieval operations for the session-get handler.
 * Provides session ID extraction and integrity-results fetching for the
 * GET /v1/integrity-session/{session_id} endpoint.
 * @module handlers/session-get/session-ops
 */

import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

/**
 * Extracts and validates the session ID from the API Gateway event.
 */
export function extractSessionId(
  event: APIGatewayProxyEventV2,
  metrics: Metrics,
): string {
  if (event.requestContext.http.method !== "GET") {
    throw new HttpError(405, "Method not allowed");
  }
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

/**
 * Fetches integrity check results from DynamoDB. Written by the ingestion
 * Lambda on POST /v1/integrity-collect; 1-hour TTL.
 */
export async function fetchIntegrityResults(
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
        Key: { session_id: { S: sessionId } },
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
      session_id: sessionId,
    });
    deps.metrics.addMetric("IntegrityResultsFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}
