import middy from "@middy/core";
import { APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from "aws-lambda";

/**
 * Configuration options for CORS headers
 */
export interface CorsConfig {
  /** Allowed HTTP methods (e.g., "GET, OPTIONS" or "POST, OPTIONS") */
  methods: string;
  /** Allowed headers (e.g., "Content-Type" or "Content-Type, Content-Encoding") */
  headers: string;
  /** Max age for preflight cache in seconds (default: 86400 = 24 hours) */
  maxAge?: string;
}

/**
 * Creates CORS headers object from configuration
 */
export function buildCorsHeaders(config: CorsConfig): Record<string, string> {
  return {
    "Access-Control-Allow-Methods": config.methods,
    "Access-Control-Allow-Headers": config.headers,
    "Access-Control-Max-Age": config.maxAge ?? "86400",
  };
}

/**
 * Middy middleware that adds CORS headers to all responses.
 * Reflects the Origin header back to support credentials.
 *
 * @param config - CORS configuration options
 * @returns Middy middleware object
 *
 * @example
 * ```typescript
 * const handler = middy(baseHandler)
 *   .use(corsMiddleware({ methods: "POST, OPTIONS", headers: "Content-Type" }))
 * ```
 */
export const corsMiddleware = (
  config: CorsConfig,
): middy.MiddlewareObj<APIGatewayProxyEventV2, APIGatewayProxyResultV2> => {
  const corsHeaders = buildCorsHeaders(config);

  return {
    after: (request) => {
      const origin = request.event.headers?.["origin"];
      if (!origin || !request.response) return;

      const response = request.response as APIGatewayProxyResultV2 & {
        headers?: Record<string, string>;
      };
      response.headers = {
        ...response.headers,
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        ...corsHeaders,
      };
    },
    onError: (request) => {
      const origin = request.event.headers?.["origin"];
      if (!origin) return;

      request.response = request.response ?? { statusCode: 500 };
      const response = request.response as APIGatewayProxyResultV2 & {
        headers?: Record<string, string>;
      };
      response.headers = {
        ...response.headers,
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        ...corsHeaders,
      };
    },
  };
};
