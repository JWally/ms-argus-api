/**
 * Base HTTP handler for ingestion endpoint.
 *
 * Provides core request handling logic for the /v1/collect endpoint,
 * including routing, SQS message dispatch, and payload archiving.
 * @module
 */
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { HttpError } from "../../helpers/http-error";
import { getSessionId, type ArgusPayload } from "../../helpers/payload-schema";

/** API Gateway event extended with pre-parsed body from middleware. */
export interface ExtendedEvent extends APIGatewayProxyEventV2 {
  /** Validated and parsed Argus payload from middleware */
  parsedBody?: ArgusPayload;
}

/** Dependencies required for the base ingestion handler. */
export interface BaseHandlerDeps {
  /** SQS client for queueing fingerprints */
  sqs: SQSClient;
  /** URL of the matching worker queue */
  sqsQueueUrl: string;
  /** Logger instance for structured logging */
  logger: Logger;
  /** Metrics client for CloudWatch metrics */
  metrics: Metrics;
}

/**
 * Route incoming request to appropriate handler.
 *
 * Handles health checks, OPTIONS preflight, and validates method/path.
 * Returns early response for health/OPTIONS, null for valid POST requests.
 *
 * @param event - API Gateway event
 * @returns Early response or null to continue processing
 * @throws HttpError for invalid method or path
 */
function routeRequest(event: ExtendedEvent): APIGatewayProxyResultV2 | null {
  if (event.rawPath === "/health") {
    return { statusCode: 200, body: JSON.stringify({ status: "healthy" }) };
  }
  const method = event.requestContext.http.method;
  if (method === "OPTIONS") {
    return { statusCode: 204 };
  }
  if (method !== "POST") {
    throw new HttpError(405, "Method not allowed");
  }
  if (event.rawPath !== "/v1/collect") {
    throw new HttpError(404, "Not found");
  }
  return null;
}

/**
 * Create the base ingestion handler function.
 *
 * Factory that returns an async handler for processing fingerprint
 * collection requests. Queues payloads to SQS for matching worker
 * and optionally archives to S3 for analysis.
 *
 * @param deps - Handler dependencies including AWS clients
 * @returns Async handler function for API Gateway events
 */
export function createBaseHandler(deps: BaseHandlerDeps) {
  return async (event: ExtendedEvent): Promise<APIGatewayProxyResultV2> => {
    const start = Date.now();

    const earlyResponse = routeRequest(event);
    if (earlyResponse) return earlyResponse;

    const payload = event.parsedBody as ArgusPayload;
    const sessionId = getSessionId(payload);

    const sqsPayload = {
      ...payload,
      _headers: {
        "User-Agent": event.headers["user-agent"],
        "Accept-Language": event.headers["accept-language"],
        "X-Forwarded-For": event.headers["x-forwarded-for"],
      },
      _timestamp: Date.now(),
    };

    try {
      await deps.sqs.send(
        new SendMessageCommand({
          QueueUrl: deps.sqsQueueUrl,
          MessageBody: JSON.stringify(sqsPayload),
        }),
      );
    } catch (err) {
      deps.logger.error("SQS send failed", {
        error: err,
        session_id: sessionId,
      });
      deps.metrics.addMetric("SqsSendFailed", MetricUnit.Count, 1);
      throw new HttpError(503, "Service temporarily unavailable");
    }

    deps.metrics.addMetric("RequestQueued", MetricUnit.Count, 1);
    deps.metrics.addMetric(
      "IngestionDuration",
      MetricUnit.Milliseconds,
      Date.now() - start,
    );

    return { statusCode: 204 };
  };
}
