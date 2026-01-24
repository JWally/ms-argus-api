import { APIGatewayProxyEventV2 } from "aws-lambda";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import middy from "@middy/core";
import { HttpError } from "../../helpers/http-error";
import { decompressPayload } from "./gzip";

export const binaryGzipBodyParser = (
  config: { maxBodyBytes: number; maxDecompressedBytes: number },
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const contentType = (event.headers["content-type"] ?? "").toLowerCase();
    if (!contentType.startsWith("application/octet-stream")) {
      if (Buffer.byteLength(event.body ?? "", "utf8") > config.maxBodyBytes) {
        metrics.addMetric("PayloadTooLarge", MetricUnit.Count, 1);
        throw new HttpError(413, "Request entity too large");
      }
      metrics.addMetric("JsonPayloadReceived", MetricUnit.Count, 1);
      return;
    }
    await decompressPayload(event, config, metrics);
  },
});

export const jsonBodyParser = (
  metrics: Metrics,
): middy.MiddlewareObj<APIGatewayProxyEventV2> => ({
  before: async (request) => {
    const { event } = request;
    const method = event.requestContext.http.method;

    if (method !== "POST") {
      return;
    }

    if (event.rawPath !== "/v1/collect") {
      return;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (event as any).parsedBody = JSON.parse(event.body ?? "{}");
    } catch {
      metrics.addMetric("InvalidJson", MetricUnit.Count, 1);
      throw new HttpError(400, "Invalid JSON payload");
    }
  },
});
