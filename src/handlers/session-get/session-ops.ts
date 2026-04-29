/**
 * @fileoverview Session retrieval operations for the session-get handler.
 *
 * Two read paths exist during the dual-key migration:
 *
 *   - {@link fetchIntegrityResultsByComposite}: the new path. Reads by
 *     `(cpi, session_id)` composite key — direct GetItem, no GSI hop.
 *     Used by the merchant-facing REST API route.
 *
 *   - {@link fetchIntegrityResultsBySessionIdLegacy}: the deprecated path.
 *     Reads via the `legacySessionIdIndex` GSI, returning the first match
 *     for a session_id regardless of cpi. Used by internal callers that
 *     still send `x-api-key` with the shared SSM secret.
 *     LEGACY_SHARED_SECRET_AUTH — drop this function alongside the route.
 *
 * @module handlers/session-get/session-ops
 */

import { APIGatewayProxyEvent, APIGatewayProxyEventV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
} from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";
import { HttpError } from "../../helpers/http-error";
import type { IntegrityResultsData } from "../../helpers/payload-schema";

/**
 * Extracts and validates `session_id` from the path. Caller is expected to
 * have already verified the HTTP method — this handler is mounted on
 * GET-only routes in both the HTTP API and REST API gateways.
 */
export function extractSessionId(
  event: APIGatewayProxyEvent | APIGatewayProxyEventV2,
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

/**
 * New path: composite-key fetch. Used by the merchant REST API route after
 * the inbound token has been verified to bind the same `cpi`.
 */
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

/**
 * LEGACY_SHARED_SECRET_AUTH — deprecated path used only by the old
 * `GET /v1/integrity-session/{session_id}` route. Reads via the
 * `legacySessionIdIndex` GSI; if multiple records exist for the same
 * session_id (different cpis), returns the first one.
 *
 * Drop alongside the route once ENABLE_LEGACY_SHARED_SECRET=false everywhere.
 */
export async function fetchIntegrityResultsBySessionIdLegacy(
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
      new QueryCommand({
        TableName: deps.integrityResultsTable,
        IndexName: "legacySessionIdIndex",
        KeyConditionExpression: "session_id = :sid",
        ExpressionAttributeValues: { ":sid": { S: sessionId } },
        Limit: 1,
      }),
    );

    if (!result.Items || result.Items.length === 0) {
      deps.metrics.addMetric("IntegrityResultsNotFound", MetricUnit.Count, 1);
      return undefined;
    }

    const item = unmarshall(result.Items[0]) as IntegrityResultsData;
    deps.metrics.addMetric("IntegrityResultsFound", MetricUnit.Count, 1);
    return item;
  } catch (error) {
    deps.logger.warn("Failed to fetch integrity results (legacy)", {
      error,
      session_id: sessionId,
    });
    deps.metrics.addMetric("IntegrityResultsFetchError", MetricUnit.Count, 1);
    return undefined;
  }
}
