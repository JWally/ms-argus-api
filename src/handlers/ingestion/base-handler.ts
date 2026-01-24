import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";
import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { S3Client } from "@aws-sdk/client-s3";
import { HttpError } from "../../helpers/http-error";
import { getSessionId, type ArgusPayload } from "../../helpers/payload-schema";
import { archivePayload } from "./archive";

export interface ExtendedEvent extends APIGatewayProxyEventV2 {
  parsedBody?: ArgusPayload;
}

export interface BaseHandlerDeps {
  sqs: SQSClient;
  sqsQueueUrl: string;
  s3: S3Client | null;
  archiveBucket: string | undefined;
  archiveSampleRate: number;
  logger: Logger;
  metrics: Metrics;
}

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

    archivePayload(sessionId, payload, {
      s3: deps.s3,
      bucket: deps.archiveBucket,
      sampleRate: deps.archiveSampleRate,
      logger: deps.logger,
      metrics: deps.metrics,
    }).catch(() => {
      /* logged in archivePayload */
    });
    deps.metrics.addMetric("RequestQueued", MetricUnit.Count, 1);
    deps.metrics.addMetric(
      "IngestionDuration",
      MetricUnit.Milliseconds,
      Date.now() - start,
    );

    return { statusCode: 204 };
  };
}
