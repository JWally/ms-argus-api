import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import { logMetrics } from "@aws-lambda-powertools/metrics/middleware";
import { injectLambdaContext } from "@aws-lambda-powertools/logger/middleware";
import middy from "@middy/core";
import httpHeaderNormalizer from "@middy/http-header-normalizer";
import warmup from "@middy/warmup";
import { onWarmup } from "../helpers/middy-helpers";
import { corsMiddleware } from "../helpers/cors-middleware";
import { jsonErrorHandler } from "../helpers/error-middleware";
import {
  binaryGzipBodyParser,
  jsonBodyParser,
  sigintTokenValidator,
} from "./ingestion/middleware";
import { createBaseHandler } from "./ingestion/base-handler";

const logger = new Logger({
  serviceName: process.env.POWERTOOLS_SERVICE_NAME ?? "argus-ingestion",
});
const metrics = new Metrics({
  namespace: process.env.POWERTOOLS_METRICS_NAMESPACE ?? "argus",
});

const MAX_BODY_BYTES = parseInt(
  process.env.MAX_BODY_BYTES ?? String(256 * 1024),
  10,
);
const MAX_DECOMPRESSED_BYTES = parseInt(
  process.env.MAX_DECOMPRESSED_BYTES ?? String(2 * 1024 * 1024),
  10,
);

const CORS_CONFIG = {
  methods: "POST, OPTIONS",
  // Mirror the custom headers the argus-integrity bundle sends on POST so
  // preflight approves them. Must stay in sync with bridge.ts request.
  headers:
    "Content-Type, Content-Encoding, X-Argus-Origin, X-Argus-Session, X-Argus-V, X-Argus-Schema-Version, X-Argus-Cpi",
};

const baseHandler = createBaseHandler({ logger, metrics });

export const handler = middy(baseHandler)
  .use(warmup({ onWarmup }))
  .use(injectLambdaContext(logger))
  .use(logMetrics(metrics))
  .use(httpHeaderNormalizer())
  .use(
    binaryGzipBodyParser(
      {
        maxBodyBytes: MAX_BODY_BYTES,
        maxDecompressedBytes: MAX_DECOMPRESSED_BYTES,
      },
      metrics,
    ),
  )
  .use(jsonBodyParser(metrics))
  .use(sigintTokenValidator(metrics))
  .use(corsMiddleware(CORS_CONFIG))
  .use(jsonErrorHandler({ logger, exposeErrors: "all" }));
